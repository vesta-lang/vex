/**
 * @file fingerprint.cpp
 * @brief Implementacion de la huella computacional por-funcion (ver
 *        analyze/fingerprint.h).
 */
#include "analyze/fingerprint.h"

#include <functional>
#include <unordered_map>
#include <unordered_set>

#include "analysis/memory/memory_access.h" // quien decide si una op toca memoria
#include "ir/ssa_ir.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include "vx/asm/asm_analyze.h"

namespace analyze {

namespace {

/* Los bytes que un tipo ocupa en el marco (el tamano de un ALLOCA) los contesta
 * el vocabulario unico (ir/ir_type_info.h) -- aqui vivia otra copia de esa
 * tabla.  El eje es el de ALMACENAMIENTO, y es justo el que necesita un
 * resumen que SUMA bytes reservados: void ocupa cero. */

/// @c true si @p op puede ALLOCAR en heap (para @c @alloc: contar todo lo que
/// pueda allocar es sound -- @c @alloc(0) solo pasa si no hay ninguno).
bool is_alloc_op(ir::IrOp op) {
    using Op = ir::IrOp;
    switch (op) {
    case Op::RAW_ALLOC:
    case Op::GC_ALLOC:
    case Op::GC_ALLOCP:
    case Op::NEWOBJ:
    case Op::NEWOBJS:
    case Op::ARRAY_ALLOC:
    case Op::STRMAKE:
    case Op::STRCAT:
    case Op::STRCONV:
    case Op::STRFLAT:
    case Op::STRRESERVE:
    case Op::STRINTERN: return true;
    default: return false;
    }
}

/// @c true si @p op NO tiene efectos de dato observables (whitelist).  Lo que
/// no esta aqui (ni es CALL/TAILCALL estatico, que se compone) se considera
/// IMPURO -> soundness: un op nuevo/desconocido bloquea @c @pure hasta
/// anadirlo. THROW/PANIC son efectos de CONTROL (se rastrean aparte), no de
/// dato -> puros. Las allocaciones son puras (una funcion pura puede construir
/// su retorno).
bool is_pure_op(ir::IrOp op) {
    using Op = ir::IrOp;
    switch (op) {
    // Constantes / movimientos / direcciones.
    case Op::CONST:
    case Op::MOV:
    case Op::NOP:
    case Op::STR_LIT_ADDR:
    case Op::LABEL_ADDR:
    case Op::SECTION_REF:
    // Aritmetica entera.
    case Op::ADD:
    case Op::SUB:
    case Op::MUL:
    case Op::DIV:
    case Op::MOD:
    case Op::NEG:
    case Op::IABS:
    case Op::IMIN:
    case Op::IMAX:
    case Op::IMINU:
    case Op::IMAXU:
    case Op::ILOG2:
    // Aritmetica float.
    case Op::FADD:
    case Op::FSUB:
    case Op::FMUL:
    case Op::FDIV:
    case Op::FNEG:
    case Op::FABS:
    case Op::FSQRT:
    case Op::FMIN:
    case Op::FMAX:
    case Op::FFLOOR:
    case Op::FCEIL:
    case Op::FROUND:
    case Op::FTRUNC:
    /* Vector.  Solo las que se quedan DENTRO de la funcion.
     *
     * VEC_UNOP / VEC_BINOP / VEC_BINOP_S / VEC_FMA estaban aqui y NO son puras:
     * su primer operando es el puntero DESTINO del bucle vectorizado, memoria
     * que viene de fuera.  El vocabulario de acceso siempre dijo que escriben;
     * esta lista decia que no, y ganaba esta -- una funcion cuyo unico trabajo
     * era rellenar el vector del llamante salia `pure_local`, y un @pure
     * declarado sobre ella se aprobaba como "puro" en vez de marcarse violado.
     *
     * Las VEC_ACC_* si se quedan: escriben en el acumulador, que el
     * vectorizador crea como un ALLOCA de la propia funcion (ver
     * `acc_slot` en vectorize.cpp).  Escribir en un local propio no es un
     * efecto que nadie de fuera pueda observar, que es justo lo que "reduccion
     * local" queria decir.  VEC_BCAST tampoco toca memoria: difunde un escalar
     * a un registro. */
    case Op::VEC_BCAST:
    case Op::VEC_ACC_ZERO:
    case Op::VEC_ACC_ADD:
    case Op::VEC_ACC_FMA:
    case Op::VEC_ACC_STORE:
    case Op::VEC_ACC_COMBINE:
    // Bitwise.
    case Op::AND:
    case Op::OR:
    case Op::XOR:
    case Op::NOT:
    case Op::SHL:
    case Op::SHR:
    case Op::SAR:
    case Op::CLZ:
    case Op::CTZ:
    case Op::POPCNT:
    case Op::BYTESWAP:
    case Op::ROTL:
    case Op::ROTR:
    // Comparaciones.
    case Op::CMP_EQ:
    case Op::CMP_NE:
    case Op::CMP_LT:
    case Op::CMP_GT:
    case Op::CMP_LE:
    case Op::CMP_GE:
    case Op::CMP_ULT:
    case Op::CMP_UGT:
    case Op::CMP_ULE:
    case Op::CMP_UGE:
    case Op::FCMP_EQ:
    case Op::FCMP_NE:
    case Op::FCMP_LT:
    case Op::FCMP_GT:
    case Op::FCMP_LE:
    case Op::FCMP_GE:
    // Casts.
    case Op::CAST:
    case Op::ZEXT:
    case Op::SEXT:
    case Op::TRUNC:
    case Op::ITOF:
    case Op::UITOF:
    case Op::FTOI:
    case Op::FTOUI:
    case Op::F32TOF64:
    case Op::F64TOF32:
    case Op::BITCAST:
    // Control de flujo (los efectos de control se rastrean aparte).
    case Op::BR:
    case Op::BR_COND:
    case Op::RET:
    case Op::UNREACHABLE:
    case Op::PHI:
    case Op::SWITCH_DENSE:
    case Op::MATCH_VARIANT:
    case Op::THROW:
    case Op::RETHROW:
    case Op::PANIC:
    case Op::TRYENTER:
    case Op::TRYLEAVE:
    case Op::LANDINGPAD:
    // Lecturas (puras; para determinismo se afinara aparte).
    case Op::LOAD:
    case Op::GETFIELD:
    case Op::ARRAY_LOAD:
    case Op::ARRAY_LEN:
    case Op::GETSTATIC:
    case Op::GEP:
    case Op::GCDEREF_IR:
    case Op::GC_DEREF_HOST:
    case Op::GC_HANDLE_FOR_PTR:
    case Op::INSTANCEOF:
    case Op::CHECKCAST:
    case Op::ISNULL:
    case Op::UNWRAP:
    case Op::REFLECT_COUNT:
    case Op::REFLECT_AT:
    case Op::FINDCLASS:
    case Op::FINDMETHOD:
    case Op::FINDFIELD:
    case Op::SHARED_STAT:
    case Op::READ_VM_REG:
    case Op::GETPROC:
    case Op::GETVM:
    case Op::GETMGR:
    case Op::GETPID:
    case Op::GETARGC:
    case Op::GETARG:
    // Alloc local + construccion de valores (allocar es puro).
    case Op::ALLOCA:
    case Op::RAW_ALLOC:
    case Op::GC_ALLOC:
    case Op::GC_ALLOCP:
    case Op::NEWOBJ:
    case Op::NEWOBJS:
    case Op::ARRAY_ALLOC:
    case Op::MAKE_VARIANT:
    case Op::MAKE_CLOSURE:
    case Op::STRMAKE:
    case Op::STRCAT:
    case Op::STRSLICE:
    case Op::STRFLAT:
    case Op::STRHASH:
    case Op::STRINTERN:
    case Op::STRRAW:
    case Op::STRCONV:
    case Op::STRRESERVE:
    case Op::STRLEN:
    case Op::STRCMP:
    case Op::STRGETBYTES:
    case Op::SPECIALIZE: return true;
    default:
        // STORE/SETFIELD/ARRAY_STORE/SETSTATIC/MEMCPY/*_FREE/ATOMIC_*/CALLN/
        // dinamicas/monitor/spawn/msg/future/DEF*/DL*/asm/... -> IMPURO.
        return false;
    }
}

} // namespace

FunctionFingerprint compute_fingerprint(const ir::IrFunction &fn,
                                        const std::string &arch) {
    FunctionFingerprint fp;
    fp.function = fn.name;

    fp.pure_local = true; // hasta encontrar un op impuro.
    /* El mismo recorrido lleva los DOS ejes.  Todo lo que rompe la pureza la
     * rompe en los dos, salvo la llamada a una nativa: ese es el unico caso que
     * se puede recuperar preguntando lo que se haya declarado de ella. */
    fp.pure_local_ignoring_natives = true;
    using Op = ir::IrOp;
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            // Allocaciones (todo lo que pueda allocar).
            if (is_alloc_op(ins.op)) ++fp.alloc_sites;
            if (ins.op == Op::MAKE_CLOSURE && (ins.imm & 0x1u))
                ++fp.alloc_sites; // env GC_HEAP.

            switch (ins.op) {
            case Op::ALLOCA:
                fp.stack_bytes += ins.imm * ir::type_storage_bytes(ins.type);
                break;
            case Op::THROW:
            case Op::RETHROW: fp.throws = true; break;
            case Op::PANIC: fp.panics = true; break;
            case Op::CALL:
            case Op::TAILCALL:
            case Op::CALLN:
                // Callgraph estatico (CALLN externo no resolvera -> conservador
                // en compose).  Neutro para la pureza LOCAL (se compone).
                if (!ins.func_name.empty()) {
                    fp.calls.push_back(ins.func_name);
                    if (ins.func_name == fn.name) fp.self_recursive = true;
                }
                // CALLN es nativo: efecto local impuro.
                if (ins.op == Op::CALLN) fp.pure_local = false;
                break;
            case Op::CALLVIRT:
            case Op::CALLM:
            case Op::CALLITF:
            case Op::CALLCLOSURE:
            case Op::CALLIND:
                fp.has_dynamic_call = true;
                fp.pure_local = false; // efecto opaco.
                fp.pure_local_ignoring_natives = false;
                break;
            case Op::INLINE_ASM: {
                // `asm { }` nativo: se ANALIZA el cuerpo (efectos exactos) en
                // vez de tratarlo como caja negra total.  El cuerpo NASM viaja
                // en
                // @c func_name (lo pone el lowering de  AS).
                /* Sin clases a proposito: de este bloque solo se preguntan
                 * el marco explicito y la pureza, y ninguna de las dos depende
                 * de QUE memoria se toca.  El nombre lo dice para que se vea
                 * que es una eleccion y no un olvido. */
                const vx::AsmBlockEffects e =
                    vx::asm_analyze_block_no_classes(ins.func_name, arch);
                // El marco EXPLICITO (push/pop/sub rsp con inmediato) SI se ve
                // en el texto -> se cuenta en el parcial medido.
                if (e.explicit_stack_bytes > 0)
                    fp.stack_bytes +=
                        static_cast<uint64_t>(e.explicit_stack_bytes);
                // Pureza AFINADA: un asm que no toca memoria, no llama y no es
                // atomico conserva la pureza local (p.ej. popcnt/aritmetica
                // sobre registros).  Un mnemonico desconocido -> conservador
                // (impuro).
                if (e.touches_mem || e.is_call || e.has_atomic || !e.known()) {
                    fp.pure_local = false;
                    fp.pure_local_ignoring_natives = false;
                }
                // Un `call` externo dentro del asm hace el efecto no acotable.
                if (e.is_call) fp.has_dynamic_call = true;
                // El marco IMPLICITO de los enlaces register() (los spills y el
                // guardado de callee-saved clobbered que decide el backend) NO
                // es visible en el texto -> el TOTAL de los callers sigue
                // usando el
                // @stack DECLARADO.  Retirarlo requiere el reporte del backend.
                fp.frame_opaque = true;
                break;
            }
            default:
                // Cualquier op no-pura y no-CALL rompe la pureza local.
                if (!is_pure_op(ins.op)) {
                    fp.pure_local = false;
                    fp.pure_local_ignoring_natives = false;
                }
                break;
            }
        }
    }
    // Totales por defecto = valores locales (se recalculan en compose).
    fp.alloc_sites_total = fp.alloc_sites;
    fp.stack_bytes_total = fp.stack_bytes;
    fp.throws_total = fp.throws;
    fp.panics_total = fp.panics;
    fp.recursive = fp.self_recursive;
    fp.effects_known = !fp.has_dynamic_call;
    fp.pure = fp.pure_local && fp.effects_known && fp.calls.empty();
    return fp;
}

std::vector<FunctionFingerprint>
compute_module_fingerprints(const ir::IrModule &mod, const std::string &arch) {
    std::vector<FunctionFingerprint> out;
    out.reserve(mod.functions.size());
    for (const auto &fn : mod.functions)
        out.push_back(compute_fingerprint(fn, arch));
    return out;
}

void compose_fingerprints(
    std::vector<FunctionFingerprint> &fps,
    const std::unordered_map<std::string, FunctionContracts> *contracts,
    const ir::IrModule *mod) {
    const size_t n = fps.size();
    if (n == 0) return;
    std::unordered_map<std::string, uint32_t> idx;
    idx.reserve(n * 2 + 1);
    for (uint32_t i = 0; i < n; ++i)
        idx.emplace(fps[i].function, i);

    // Marco de pila PROPIO a efectos del TOTAL: normalmente el medido
    // (`stack_bytes`), pero para una fn de marco OPACO (`asm { }`, cuyo frame
    // no se ve en el IR) se usa su @stack DECLARADO -- asi el total de sus
    // callers refleja la pila real de la primitiva de asm.  No toca el parcial
    // medido (la verificacion del parcial sigue siendo cota superior sobre 0).
    auto frame_para_total = [&](uint32_t v) -> uint64_t {
        const auto &f = fps[v];
        if (f.frame_opaque && contracts) {
            // El contrato se declara con el nombre SIMPLE (`atomic_cas64`)
            // pero el IR trae la fn mangled por modulo (`atomic__atomic_
            // cas64`).  Se prueba el completo y luego el simple (ultimo `__`).
            const FunctionContracts *c = nullptr;
            auto it = contracts->find(f.function);
            if (it != contracts->end()) {
                c = &it->second;
            } else {
                const size_t p = f.function.rfind("__");
                if (p != std::string::npos) {
                    auto it2 = contracts->find(f.function.substr(p + 2));
                    if (it2 != contracts->end()) c = &it2->second;
                }
            }
            if (c) {
                if (c->stack_partial >= 0)
                    return static_cast<uint64_t>(c->stack_partial);
                if (c->stack_total >= 0)
                    return static_cast<uint64_t>(c->stack_total);
            }
        }
        return f.stack_bytes;
    };

    // Para cada funcion, DFS del cierre transitivo por el callgraph estatico.
    // O(F*(V+E)) -- aceptable para tamanos de modulo tipicos.
    std::vector<char> visited(n, 0);
    std::vector<uint32_t> stack;
    stack.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        std::fill(visited.begin(), visited.end(), 0);
        stack.clear();
        stack.push_back(i);
        uint32_t alloc_total = 0;
        bool throws_t = false, panics_t = false, recursive = false;
        bool known = true, all_pure_local = true;
        /* Quien lo hace opaco.  Se queda el PRIMERO que se encuentra: decir
         * uno concreto es accionable, y una lista de doce solo abruma -- si al
         * declarar ese sigue habiendo mas, el aviso vuelve a salir con el
         * siguiente, que es como se arregla una cadena. */
        std::string opaque_callee;
        bool opaque_dynamic = false;
        while (!stack.empty()) {
            const uint32_t v = stack.back();
            stack.pop_back();
            if (visited[v]) continue;
            visited[v] = 1;
            const auto &f = fps[v];
            alloc_total += f.alloc_sites;
            throws_t = throws_t || f.throws;
            panics_t = panics_t || f.panics;
            /* Con el modulo delante, las nativas dejan de ser un motivo de
             * impureza POR SI SOLAS: son aristas del grafo como cualquier otra
             * y se resuelven abajo, consultando lo declarado.  Sin modulo se usa
             * el eje conservador, que es el de siempre.
             *
             * La seguridad no depende de esta eleccion: una nativa sin declarar
             * pone `known` en falso mas abajo, y `pure` exige las dos cosas. */
            all_pure_local =
                all_pure_local &&
                (mod != nullptr ? f.pure_local_ignoring_natives : f.pure_local);
            if (f.has_dynamic_call) {
                known = false; // efecto opaco alcanzable.
                opaque_dynamic = true;
            }
            for (const auto &callee : f.calls) {
                auto it = idx.find(callee);
                if (it == idx.end()) {
                    /* No esta en el programa.  Antes eso bastaba para dar el
                     * cierre por opaco; ahora se PREGUNTA primero si alguien
                     * dijo lo que hace.
                     *
                     * Lo declarado se aporta como lo que es -- una afirmacion
                     * de quien importa la funcion --, y el cierre sigue siendo
                     * conocido.  Cada eje que la declaracion NO cubre se queda
                     * en su valor conservador y no en el permisivo: un campo
                     * que nadie puso vale `false`, y `false` aqui significa
                     * "no aporta ese efecto", asi que solo puede aprobar de mas
                     * si el que declara MINTIO -- que es su responsabilidad, no
                     * un descuido nuestro. */
                    const ir::IrNativeEffects *d =
                        mod != nullptr ? mod->native_effects_of(callee)
                                       : nullptr;
                    if (d == nullptr) {
                        known = false; // nadie ha dicho nada -> conservador.
                        if (opaque_callee.empty()) opaque_callee = callee;
                        continue;
                    }
                    throws_t = throws_t || d->may_throw;
                    panics_t = panics_t || d->may_panic;
                    if (d->allocates) ++alloc_total;
                    /* La pureza cae con cualquier efecto de dato observable.
                     * Una nativa que solo lee sus argumentos y no toca nada mas
                     * SI puede ser pura, que es justo lo que permite demostrar
                     * un `@pure` sobre codigo que llama a `strlen`. */
                    if (d->writes_pointee != 0 || d->writes_global ||
                        d->reads_global || d->io || d->nondeterministic)
                        all_pure_local = false;
                    continue;
                }
                const uint32_t j = it->second;
                if (j == i)
                    recursive = true; // arista de vuelta al inicio -> ciclo.
                if (!visited[j]) stack.push_back(j);
            }
        }
        fps[i].alloc_sites_total = alloc_total;
        fps[i].recursive = recursive || fps[i].self_recursive;
        fps[i].effects_known = known;
        fps[i].opaque_callee = std::move(opaque_callee);
        fps[i].opaque_dynamic = opaque_dynamic;
        // Si no conocemos todos los efectos alcanzables, los totales de efecto
        // se vuelven CONSERVADORES: no podemos PROBAR la ausencia.
        fps[i].throws_total = known ? throws_t : true;
        fps[i].panics_total = known ? panics_t : true;
        // Pura sii TODA funcion alcanzable es localmente pura Y conocemos todos
        // los efectos (sin dinamica ni externos no resueltos).
        fps[i].pure = all_pure_local && known;
    }

    // stack_bytes_total = profundidad de pila PEOR CASO = frame propio + el
    // MAXIMO de los callees (la cadena de llamadas mas honda), NO la suma del
    // conjunto alcanzable (a diferencia de alloc_total): la pila se libera al
    // volver, asi que solo importa el camino mas profundo.  Un ciclo del
    // callgraph (recursion) o un callee externo hacen la profundidad NO
    // acotable -> sentinela STACK_UNBOUNDED, que verify trata como
    // inverificable.  DFS post-orden ITERATIVO (pila explicita, NO recursion
    // de C++: un modulo con una cadena de llamadas muy honda -- p.ej. codigo
    // generado en comptime -- desbordaria la pila del proceso).  Gris (en
    // pila) = deteccion de ciclo (arista de vuelta).
    std::vector<uint64_t> memo(n, 0);
    std::vector<char> st(n, 0); // 0=blanco, 1=gris (en pila), 2=negro (hecho)
    // Cada marco: (nodo, fase).  fase 0 = ENTRAR (marcar gris + apilar hijos);
    // fase 1 = SALIR (todos los hijos hechos -> componer el maximo).
    std::vector<std::pair<uint32_t, uint8_t>> dfs;
    dfs.reserve(n);
    for (uint32_t s = 0; s < n; ++s) {
        if (st[s] != 0) continue;
        dfs.push_back({s, 0});
        while (!dfs.empty()) {
            const uint32_t v = dfs.back().first;
            const uint8_t fase = dfs.back().second;
            if (fase == 0) {
                if (st[v] == 2) {
                    dfs.pop_back();
                    continue;
                }
                st[v] = 1;             // gris (en pila)
                dfs.back().second = 1; // al desapilar, componer
                for (const auto &callee : fps[v].calls) {
                    auto it = idx.find(callee);
                    if (it == idx.end()) continue; // externo -> se ve en SALIR
                    const uint32_t j = it->second;
                    if (st[j] == 0) dfs.push_back({j, 0});
                }
            } else {
                dfs.pop_back();
                uint64_t best = 0; // maximo de los callees
                for (const auto &callee : fps[v].calls) {
                    auto it = idx.find(callee);
                    if (it == idx.end()) {
                        best = STACK_UNBOUNDED;
                        break;
                    }
                    const uint32_t j = it->second;
                    // Callee gris = arista de vuelta (ciclo); negro = hecho.
                    const uint64_t d = (st[j] == 1) ? STACK_UNBOUNDED : memo[j];
                    if (d == STACK_UNBOUNDED) {
                        best = STACK_UNBOUNDED;
                        break;
                    }
                    if (d > best) best = d;
                }
                memo[v] = (best == STACK_UNBOUNDED)
                              ? STACK_UNBOUNDED
                              : frame_para_total(v) + best;
                st[v] = 2; // negro (hecho)
            }
        }
    }
    for (uint32_t i = 0; i < n; ++i)
        fps[i].stack_bytes_total = memo[i];
}

std::vector<ContractCheck> verify_contracts(
    const std::vector<FunctionFingerprint> &fps,
    const std::unordered_map<std::string, FunctionContracts> &contracts) {
    std::vector<ContractCheck> out;
    if (contracts.empty()) return out;
    // Nombre SIMPLE (ultimo segmento): el IR puede venir mangled por namespace
    // (ns__f) o cualificado (ns.f); el contrato se declara con el nombre
    // simple.
    auto simple = [](const std::string &q) -> std::string {
        size_t p = q.rfind("__");
        if (p != std::string::npos) return q.substr(p + 2);
        p = q.rfind('.');
        return (p == std::string::npos) ? q : q.substr(p + 1);
    };
    // Indice por nombre COMPLETO y por nombre simple.  Los contratos de un
    // METODO se declaran como `Tipo__metodo` -- el nombre simple no vale como
    // clave porque dos tipos pueden tener un metodo homonimo --, mientras que
    // los de una funcion libre se declaran con el nombre simple aunque el IR la
    // traiga mangled por namespace.  Indexando por los dos, una sola busqueda
    // cubre ambos.  ANTES solo se indexaba el simple: `simple("S__mal")` da
    // "mal", la clave del contrato es "S__mal", la busqueda fallaba y el
    // `continue` se tragaba el contrato EN SILENCIO -- o sea que ningun
    // @pure/@alloc/@stack/@nothrow/@nopanic sobre un metodo se verificaba
    // nunca.
    std::unordered_map<std::string, const FunctionFingerprint *> byname;
    byname.reserve(fps.size() * 4 + 1);
    for (const auto &f : fps) {
        byname.emplace(f.function, &f);
        byname.emplace(simple(f.function), &f);
    }

    using St = ContractCheck::Status;
    for (const auto &kv : contracts) {
        const std::string &name = kv.first;
        const FunctionContracts &c = kv.second;
        if (!c.any()) continue;

        // Reunir TODAS las huellas a las que aplica el contrato.  Casi siempre
        // es una, pero el contrato de un metodo de PLANTILLA es una promesa
        // para CADA instanciacion, asi que hay que comprobarlo contra todas:
        // si `atomic<T>::swap` declara @alloc(0) y `atomic<f64>::swap` aloca,
        // eso es un incumplimiento aunque `atomic<i64>::swap` cumpla.
        std::vector<const FunctionFingerprint *> targets;
        auto it = byname.find(name);
        if (it != byname.end()) {
            targets.push_back(it->second);
        } else {
            // El metodo DENTRO de un namespace: la clave es `Tipo__metodo` y el
            // IR trae `ns__Tipo__metodo`.  Por sufijo, y solo si el resultado
            // es unico (si no, seria adivinar).
            //
            // Un metodo de PLANTILLA no necesita nada especial aqui: la
            // monomorphizacion COPIA los contratos a cada instanciacion, asi
            // que `atomic<T>::swap` se verifica como `atomic_i64__swap` por la
            // via exacta -- una vez por instanciacion, que es justo lo que
            // promete el contrato.
            const std::string suf = "__" + name;
            const FunctionFingerprint *uniq = nullptr;
            for (const auto &f : fps) {
                if (f.function.size() > suf.size() &&
                    f.function.compare(f.function.size() - suf.size(),
                                       suf.size(), suf) == 0) {
                    if (uniq) {
                        uniq = nullptr;
                        break;
                    } // ambiguo
                    uniq = &f;
                }
            }
            if (uniq) targets.push_back(uniq);
        }
        if (targets.empty()) continue; // no llego al IR (inline/DCE).

        for (const FunctionFingerprint *fpp : targets) {
            const FunctionFingerprint &fp = *fpp;

            // Con varias instanciaciones, el informe dice CUAL falla:
            // "atomic__swap" a secas no distinguiria el i64 del f64.
            const std::string etiqueta =
                (targets.size() > 1) ? (name + " [" + fp.function + "]") : name;
            auto add = [&](const char *cn, St st, std::string detail) {
                out.push_back({etiqueta, cn, st, std::move(detail)});
            };

            // @pure: probado puro -> OK; probado impuro (efectos conocidos) ->
            // VIOLATED; si no se conocen los efectos -> UNVERIFIABLE.
            if (c.pure) {
                if (fp.pure)
                    add("@pure", St::OK, "puro");
                else if (fp.effects_known)
                    add("@pure", St::VIOLATED,
                        "la funcion tiene efectos de dato");
                else
                    add("@pure", St::UNVERIFIABLE,
                        "efectos desconocidos (llamada dinamica/externa)");
            }
            // @nothrow.
            if (c.nothrow) {
                if (fp.effects_known && !fp.throws_total)
                    add("@nothrow", St::OK, "no lanza");
                else if (fp.effects_known && fp.throws_total)
                    add("@nothrow", St::VIOLATED,
                        "puede lanzar (throw alcanzable)");
                else
                    add("@nothrow", St::UNVERIFIABLE, "efectos desconocidos");
            }
            // @nopanic.
            if (c.nopanic) {
                if (fp.effects_known && !fp.panics_total)
                    add("@nopanic", St::OK, "no hace panic");
                else if (fp.effects_known && fp.panics_total)
                    add("@nopanic", St::VIOLATED, "puede hacer panic");
                else
                    add("@nopanic", St::UNVERIFIABLE, "efectos desconocidos");
            }
            // @alloc: PARCIAL = sitios PROPIOS (exacto); TOTAL = cierre
            // alcanzable (conservador si hay efectos desconocidos).  Se declara
            // cualquiera de las dos (o ambas).  La forma corta `@alloc(N)` fija
            // el TOTAL.
            if (c.alloc_partial >= 0) {
                const uint64_t got = fp.alloc_sites;
                const uint64_t want = static_cast<uint64_t>(c.alloc_partial);
                std::string d = "parcial: esperado <=" + std::to_string(want) +
                                ", inferido " + std::to_string(got) +
                                " (propio)";
                add("@alloc", got > want ? St::VIOLATED : St::OK, std::move(d));
            }
            if (c.alloc_total >= 0) {
                const uint64_t got = fp.alloc_sites_total;
                const uint64_t want = static_cast<uint64_t>(c.alloc_total);
                std::string d = "total: esperado <=" + std::to_string(want) +
                                ", inferido " + std::to_string(got);
                if (got > want)
                    add("@alloc", St::VIOLATED, std::move(d));
                else if (fp.effects_known)
                    add("@alloc", St::OK, std::move(d));
                else
                    add("@alloc", St::UNVERIFIABLE,
                        d + " (mas posibles: efectos desconocidos)");
            }
            // @stack: PARCIAL = frame PROPIO (exacto, siempre verificable);
            // TOTAL = profundidad de pila peor caso del arbol de llamadas.  Si
            // el total no es acotable (recursion/callee externo) queda
            // INVERIFICABLE.  Forma corta `@stack(N)` = TOTAL.
            if (c.stack_partial >= 0) {
                const uint64_t got = fp.stack_bytes;
                const uint64_t want = static_cast<uint64_t>(c.stack_partial);
                std::string d = "parcial: esperado <=" + std::to_string(want) +
                                "B, inferido " + std::to_string(got) +
                                "B (frame propio)";
                add("@stack", got > want ? St::VIOLATED : St::OK, std::move(d));
            }
            if (c.stack_total >= 0) {
                const uint64_t got = fp.stack_bytes_total;
                const uint64_t want = static_cast<uint64_t>(c.stack_total);
                if (got == STACK_UNBOUNDED)
                    add("@stack", St::UNVERIFIABLE,
                        "total: no acotable (recursion o callee externo)");
                else {
                    std::string d =
                        "total: esperado <=" + std::to_string(want) +
                        "B, inferido " + std::to_string(got) +
                        "B (peor caso de pila)";
                    add("@stack", got > want ? St::VIOLATED : St::OK,
                        std::move(d));
                }
            }
        } // for targets
    }
    return out;
}

std::vector<ContractCheck> verify_type_contracts(
    const std::vector<TypeFingerprint> &fps,
    const std::unordered_map<std::string, TypeContracts> &contracts) {
    std::vector<ContractCheck> out;
    if (contracts.empty()) return out;
    // Indice por nombre de tipo (el nombre del contrato es el nombre
    // declarado).
    std::unordered_map<std::string, const TypeFingerprint *> byname;
    byname.reserve(fps.size() * 2 + 1);
    for (const auto &f : fps)
        byname.emplace(f.type_name, &f);

    using St = ContractCheck::Status;
    for (const auto &kv : contracts) {
        const std::string &name = kv.first;
        const TypeContracts &c = kv.second;
        if (!c.any()) continue;
        auto it = byname.find(name);
        if (it == byname.end()) continue; // el tipo no llego al layout.
        const TypeFingerprint &fp = *it->second;

        auto add = [&](const char *cn, St st, std::string detail) {
            out.push_back({name, cn, st, std::move(detail)});
        };

        // @pod: value-type trivialmente copiable (sin dtor ni campos
        // gestionados). Decidible del layout -> OK / VIOLATED (nunca
        // UNVERIFIABLE).
        if (c.pod) {
            if (fp.is_pod) {
                add("@pod", St::OK, "value-type trivialmente copiable");
            } else {
                std::string why =
                    fp.is_reference
                        ? "es un tipo por referencia (clase), no un value-type"
                    : fp.has_destructor
                        ? "tiene destructor (~Tipo) -> carril move-only"
                        : "tiene algun campo gestionado "
                          "(heap/GC/smart-pointer)";
                add("@pod", St::VIOLATED, std::move(why));
            }
        }
        // @no_heap: ningun campo referencia el heap gestionado.
        if (c.no_heap) {
            add("@no_heap", fp.no_heap ? St::OK : St::VIOLATED,
                fp.no_heap ? "sin campos en el heap gestionado"
                           : "algun campo referencia el heap gestionado");
        }
        // @size(N): tamano EXACTO (estabilidad de ABI).  Decidible del layout.
        if (c.size >= 0) {
            const uint64_t got = fp.size_bytes;
            const uint64_t want = static_cast<uint64_t>(c.size);
            std::string d = "esperado " + std::to_string(want) +
                            "B, inferido " + std::to_string(got) + "B";
            add("@size", got == want ? St::OK : St::VIOLATED, std::move(d));
        }
    }
    return out;
}

size_t report_native_effect_conflicts(const ir::IrModule &mod,
                                      const std::string &file,
                                      vx::Diagnostics &diags) {
    size_t n = 0;
    for (const ir::IrNativeImport &ni : mod.native_imports) {
        if (!ni.effects_conflict) continue;
        ++n;
        // Se nombra QUE eje choca, no solo que hay choque: "difieren" sin decir
        // en que obliga a ir a leer las dos declaraciones para saber si importa
        // -- y muchas veces no importa.
        std::string ejes;
        const ir::IrNativeEffects &e = ni.effects;
        auto anota = [&ejes](const char *nombre) {
            if (!ejes.empty()) ejes += ", ";
            ejes += nombre;
        };
        // Se listan los ejes que la union acabo ATRIBUYENDO: son exactamente
        // los que alguna de las dos afirmo y por los que el llamante paga.
        if (e.writes_pointee != 0) anota("writes_pointee");
        if (e.reads_pointee != 0) anota("reads_pointee");
        if (e.writes_global) anota("writes_global");
        if (e.reads_global) anota("reads_global");
        if (e.io) anota("io");
        if (e.may_throw) anota("may_throw");
        if (e.may_panic) anota("may_panic");
        if (e.allocates) anota("allocates");
        if (e.nondeterministic) anota("nondeterministic");
        diags.diag(vx::SourceLoc{}, vx::DiagLevel::WARN, "VXT008",
                   {ni.lib, ni.name, ejes});
    }
    (void)file;
    return n;
}

ContractReport report_contract_checks(const std::vector<ContractCheck> &checks,
                                      const std::string &file,
                                      vx::Diagnostics &diags) {
    ContractReport r;
    for (const ContractCheck &ck : checks) {
        vx::SourceLoc loc;
        loc.file = file;
        switch (ck.status) {
        case ContractCheck::VIOLATED:
            /* Demostrado que no se cumple: es un error del programa, y por eso
             * aborta la construccion.  El llamante decide -- en `--analyze` se
             * mide y se ensena, no se construye. */
            ++r.violated;
            diags.diag(loc, vx::DiagLevel::ERR, "VXT004",
                       {ck.function, ck.contract, ck.detail});
            break;
        case ContractCheck::UNVERIFIABLE:
            /* Y este es el que se descartaba en silencio.  NO es un error: el
             * programa puede estar perfectamente bien y ser el ANALISIS el que
             * no llega.  Pero callarselo deja un contrato que nadie comprueba y
             * que parece comprobado, asi que se dice -- con el motivo dentro,
             * que es lo que lo vuelve accionable. */
            ++r.unverified;
            diags.diag(loc, vx::DiagLevel::WARN, "VXW001",
                       {ck.function, ck.contract, ck.detail});
            break;
        case ContractCheck::OK:
        default:
            /* Se cumple y esta demostrado: no hay nada que decir.  Decirlo
             * seria ruido en cada compilacion, y el sitio donde SI se ensena es
             * el volcado del ASA, que para eso ensena tambien lo verde. */
            break;
        }
    }
    return r;
}

} // namespace analyze
