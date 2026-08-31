/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir_effects.cpp
 * @brief Motor IR -> SemanticEffects.  El asm lifteado NO es especial: entra
 *        como ADD/LOAD/STORE/... normales.  Solo el residuo opaco (INLINE_ASM/
 *        ASM_MICRO) se analiza aparte, conservador y con tags.
 */
#include "util/env_flags.h"
#include <cctype>
#include "analysis/effects/ir_effects.h"

#include "util/crono_tramo.h"
#include "analysis/facts/asm_bindings.h" // de que valor habla cada operando
#include "analysis/memory/memory_access.h"

#include "ir/ssa_ir.h"
#include "vx/asm/asm_analyze.h"
#include "vx/asm/asm_effects.h" // canonicalizar el registro base (por arch)
#include "aot/aot_analyze.h" // que necesita cada op para correr (backend AOT)

#include <algorithm>
#include "util/reloj.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>

namespace analysis {
namespace effects {

using ::aot::aot_classify_op;
using ::aot::AotOpClass;
using ir::IrOp;

bool funcion_tiene_asm(const ir::IrFunction &fn) {
    for (const ir::IrBlock &b : fn.blocks)
        for (const ir::IrInstr &in : b.instrs)
            /* Los TRES.  `RAW_ASM` es una funcion `@Asm` entera, y faltaba:
             * quien pregunta esto lo hace para decidir si vale la pena traer
             * los hechos que el asm necesita, asi que dejarse una forma fuera
             * no da un error -- da menos conocimiento, en silencio, justo
             * donde el compilador tiene que entender codigo que no escribio
             * el.  El runtime de excepciones es `@Asm`. */
            if (in.op == ir::IrOp::RAW_ASM || in.op == ir::IrOp::INLINE_ASM ||
                in.op == ir::IrOp::ASM_MICRO)
                return true;
    return false;
}

// --------------------------------------------------------------------------
// Clasificacion de punteros a AbstractLoc -- delega en el RESOLVEDOR COMPARTIDO
// (analysis/memory/points_to), que es la unica fuente de "a que memoria apunta
// este puntero" para efectos Y para el DSE.  Antes habia aqui un classify_rec
// duplicado; se elimino para tener un solo modelo.
// --------------------------------------------------------------------------
AbstractLoc classify_ptr(const ir::IrFunction &fn,
                         const analysis::IrFacts &facts, ir::IrValueId ptr) {
    // Conveniencia (tests / llamadas sueltas): construye una tabla local.  El
    // camino caliente (por-instr) usa la tabla cacheada via effects_of_instr.
    analysis::PointsTo pt = analysis::compute_points_to(fn, facts);
    return analysis::loc_of(pt, ptr, 0 /*ancho desconocido = objeto entero*/);
}

// Bytes accedidos por un LOAD/STORE: delega en la UNICA verdad compartida.
static int32_t access_bytes(ir::IrType t) {
    return analysis::memory_access_size(t);
}

// --------------------------------------------------------------------------
// Efecto local de una instruccion opaca de asm (INLINE_ASM / ASM_MICRO).
// --------------------------------------------------------------------------
static EffectAnalysisResult opaque_asm_effects(const ir::IrFunction &fn,
                                               const analysis::PointsTo &pt,
                                               const ir::IrInstr &ins,
                                               const EffectEnv &env) {
    EffectAnalysisResult r;
    // func_name lleva el cuerpo NASM (lo pone el lowering de asm).  El analisis
    // de bloque del asm opaco vive en el modulo asm (namespace vx).
    /* La arquitectura sale del OBJETIVO, no escrita a mano.  Estaba clavada a
     * x86, asi que al compilar para ARM este analisis leia `ldr x0, [x1]` con
     * la tabla de x86: mnemonico desconocido, registro desconocido, y el bloque
     * acababa valiendo "puede hacer cualquier cosa" -- ademas de aparecer como
     * una laguna del analisis que no existia. */
    /* De que CLASE es cada operando.  Sin ese diccionario, un
     * `vmovdqu [$0 + 0x1e0], $11` no puede decir que toca treinta y dos bytes:
     * el ancho lo da el operando que no son los corchetes, y cuando lo eligio
     * el compilador se llama `$11` y solo su clase declarada lo sabe.
     *
     * Lo tenia el camino que comprueba la alineacion y no el que calcula los
     * efectos, asi que aqui cada acceso quedaba sin ancho -> sin extension ->
     * "toca el objeto entero", y la comprobacion de limites no podia decir
     * nada.  Un `asm` que escribia mas alla del buffer del llamante pasaba sin
     * un aviso, y lo que hay detras del buffer es la siguiente variable. */
    /* Si quien pregunta ya las tiene, se usan: son un hecho de la FUNCION y
     * rehacerlas por instruccion es el grueso del coste de este analisis. */
    analysis::AsmBindingFacts propias;
    const analysis::AsmBindingFacts *ligp = env.asm_bindings;
    if (ligp == nullptr) {
        propias = analysis::compute_asm_bindings(fn);
        ligp = &propias;
    }
    const analysis::AsmBindingFacts &lig = *ligp;
    std::vector<std::pair<std::string, std::string>> clases;
    {
        util::CronoTramo crono__("  efectos:armar-clases");
        clases.reserve(lig.ligaduras.size());
        for (const analysis::LigaduraAsm &l : lig.ligaduras)
            clases.emplace_back(l.marcador, l.clase);
    }
    /* EL TEXTO A ANALIZAR, que no siempre esta donde estaba.
     *
     * Un `INLINE_ASM` lleva su cuerpo en `func_name`.  Un `ASM_MICRO` NO: lleva
     * el indice de su ficha en `imm`, y el texto esta en la ficha.  Se
     * analizaba `func_name` en los dos casos, asi que para todo bloque ELEVADO
     * se analizaba la cadena VACiA -- cero accesos, cero efectos de memoria --.
     * Y eso no da error: da una funcion que escribe memoria declarada `pure
     * readonly`, y con ella un llamante que se queda con el valor viejo en un
     * registro.
     *
     * Ademas hay que reponer los CORCHETES.  La plantilla de un micro lleva el
     * operando pelado (`movdqa $0, $1`) porque como se escribe una direccion
     * depende de la ISA y eso se decide al sustituir.  El detector de accesos
     * busca corchetes -- con razon: es lo que distingue tocar memoria de mover
     * entre registros --, asi que sin ellos no ve ninguno.  La informacion no
     * falta, esta en la ficha: el operando dice que es de memoria. */
    std::string texto_asm = ins.func_name;
    if (ins.op == ir::IrOp::ASM_MICRO && ins.imm < fn.asm_micros.size()) {
        const ir::AsmMicro &am = fn.asm_micros[ins.imm];
        texto_asm = am.tmpl;
        for (size_t k = 0; k < am.operands.size(); ++k) {
            if (am.operands[k].kind != ir::AsmOperandKind::MEM) continue;
            const std::string marcador = "$" + std::to_string(k);
            /* Se busca el marcador EXACTO: `$1` no debe casar dentro de `$10`.
             */
            size_t p = 0;
            while ((p = texto_asm.find(marcador, p)) != std::string::npos) {
                const size_t fin = p + marcador.size();
                const bool solo = fin >= texto_asm.size() ||
                                  !std::isdigit((unsigned char)texto_asm[fin]);
                if (solo) {
                    texto_asm.insert(fin, "]");
                    texto_asm.insert(p, "[");
                    p = fin + 2;
                } else {
                    p = fin;
                }
            }
        }
    }
    vx::AsmBlockEffects e;
    {
        /* En su propio bloque: mide SOLO el analisis del texto del bloque. */
        util::CronoTramo crono__("  efectos:analizar-bloque-asm");
        e = vx::asm_analyze_block(texto_asm, vx::asm_arch_actual(), clases);
    }
    /* Se declara SOLO lo que el bloque hace.  Antes, cualquier asm que tocara
     * memoria se anotaba como lectura Y escritura de todo, y eso lo convierte
     * en una barrera para cuanto haya alrededor: un `mov rax, [rdi]` impedia
     * mover una escritura, subir una lectura fuera de un bucle o eliminar una
     * escritura muerta.  El analisis del asm ya distingue las dos cosas -- la
     * tabla dice que operandos escribe cada instruccion -- y ante cualquier
     * duda marca las dos, asi que esto no afloja nada. */
    /* Y se dice QUE memoria cuando se puede.  El bloque llega a ella por un
     * registro, y ese registro esta LIGADO a una variable del programa, asi que
     * hay camino: registro -> ligadura -> hueco de la variable -> lo que se
     * guardo en el.  Con eso, un `asm` que escribe en `[rdi]` afirma la
     * localizacion de `*q` en vez de "cualquier sitio", y deja de estorbar a lo
     * que toca OTRA memoria.
     *
     * Solo si se pueden atribuir TODOS los accesos: uno sin atribuir significa
     * que el bloque toca algo que no sabemos nombrar, y entonces la lista no
     * describe el total.  Igual con las ligaduras que aun no tienen registro
     * (lo elige el asignador despues): no se pueden emparejar por nombre. */
    /* `VESTA_ASM_LOC=0` vuelve a "toca memoria en algun sitio", que es como
     * estaba.  Mismo criterio que `VESTA_TRAMOS` o `VESTA_SCHED_ALIAS`.
     *
     * MEDIDO (2026-08-06): con el y sin el, el codigo generado sale IDENTICO en
     * los 48 programas del corpus que llevan asm.  No es que la precision no
     * valga -- se ve en `--analyze`, donde un bloque pasa de "cualquier sitio"
     * a `stack#0` --: es que NINGUN consumidor la mira todavia.  El DSE y el
     * planificador tratan un `INLINE_ASM` como barrera TOTAL, escrito a mano en
     * su propio switch ("mas adelante los eff bits de la DB afinan", dice el
     * comentario de alli desde hace tiempo).
     *
     * O sea que esto esta listo y esperando a que alguien pregunte.  Cablear al
     * DSE es el siguiente paso, y tiene su cuidado: un asm lee los valores de
     * sus variables ligadas aunque no toque memoria, asi que una escritura al
     * hueco de una de ellas NO esta muerta. */
    static const bool loc_activa = util::flag_on(util::FlagId::AsmLoc);
    bool localizado =
        loc_activa && !e.accesos.empty() && !e.accesos_incompletos;
    /* Que dice el analisis del TEXTO de este bloque, en crudo.
     *
     * Existe porque la cadena que va de aqui a los contratos tiene varios pasos
     * y cada uno puede perder la escritura -- el analisis del texto, la
     * localizacion, el filtro de lo observable, el cierre --.  Sin ver el
     * primer eslabon, buscar en los otros es adivinar, y adivinar aqui sale
     * caro: `readonly` sobre una funcion que escribe hace que su llamante se
     * quede con el valor viejo. */
    if (util::flag_on(util::FlagId::AsmEffDebug)) {
        std::fprintf(stderr,
                     "[asm-eff] %s: accesos=%zu incompletos=%d mem_r=%d "
                     "mem_w=%d localizado=%d\n",
                     fn.name.c_str(), e.accesos.size(),
                     (int)e.accesos_incompletos, (int)e.reads_mem,
                     (int)e.writes_mem, (int)localizado);
        for (const auto &a : e.accesos)
            std::fprintf(
                stderr, "[asm-eff]   base=<%s> escribe=%d desde_memoria=%d\n",
                a.base.c_str(), (int)a.escribe, (int)a.desde_memoria.hay);
    }
    std::vector<AbstractLoc> locs_lee, locs_escribe;
    if (localizado) {
        /* De que valor habla cada operando lo responde UN solo sitio.  Antes
         * este recorrido -- marcador, ligadura, hueco, contenido -- estaba
         * copiado aqui, en el eliminador de escrituras muertas y en la
         * comprobacion de precondiciones del asm; tres copias del mismo camino
         * acaban siendo tres respuestas distintas a la misma pregunta. */
        /* Rangos de la funcion: es lo que cierra la extension de un acceso
         * cuando lo que la determina no es una constante sino un operando --
         * `rep movsb` recorre `rcx` bytes, y `rcx` es una variable con rango.
         * Se calculan una vez por bloque, no por acceso. */
        /* Se cronometran por separado: reconstruir el def-use y recorrer la
         * funcion entera son dos costes distintos con arreglos distintos, y el
         * segundo ya tiene cache -- pero devuelve por VALOR, asi que un acierto
         * sigue copiando el estado de todos los bloques. */
        static std::atomic<long long> ns_hechos{0}, ns_rangos{0};
        static std::atomic<long long> n_veces{0};
        const uint64_t t0 = util::reloj::ahora();
        /* Si el entorno los trae, no se recalculan: es el mismo trato que las
         * ligaduras de asm.  El puntero se SUJETA aparte de la referencia para
         * que no quede colgando si hay que calcularlos aqui. */
        std::shared_ptr<const analysis::RangeFacts> rangos_propios;
        analysis::IrFacts hechos_propios;
        const uint64_t t1 = util::reloj::ahora();
        // Solo valen si son de ESTA funcion; si no, se recalculan.
        const bool tengo = env.rangos != nullptr && env.rangos_de == &fn;
        if (!tengo) {
            hechos_propios = analysis::build_ir_facts(fn);
            rangos_propios = analysis::compute_ranges_ptr(fn, hechos_propios);
        }
        const analysis::RangeFacts &rangos =
            tengo ? *env.rangos : *rangos_propios;
        const uint64_t t2 = util::reloj::ahora();
        ns_hechos += util::reloj::a_ns(t1 - t0);
        ns_rangos += util::reloj::a_ns(t2 - t1);
        if ((++n_veces % 200) == 0 && util::flag_on(util::FlagId::Times))
            std::fprintf(
                stderr,
                "[asm-efectos] %lld veces | def-use %lld ms | rangos %lld ms\n",
                n_veces.load(), ns_hechos.load() / 1000000,
                ns_rangos.load() / 1000000);
        for (const vx::AsmBlockEffects::Acceso &a : e.accesos) {
            /* TODAS las que responden a ese nombre.  Aqui no hace falta saber
             * cual de ellas es: nombrar las dos dice que el acceso va por una
             * de estas, y eso sigue siendo MUCHISIMO menos que "cualquier
             * sitio" -- que es donde caia antes en cuanto dos variables de
             * ambitos distintos compartian registro. */
            const auto cands = lig.candidatas(a.base);
            if (cands.empty()) {
                localizado = false;
                break;
            }
            /* Hasta donde llega el acceso.  Con la extension resuelta se dice
             * QUE BYTES toca en vez de dar el objeto entero por tocado, y esa
             * es la diferencia entre que dos accesos al mismo objeto se
             * estorben siempre o solo cuando de verdad se pisan.
             *
             * Una base que se cargo de memoria (@c desde_memoria) se describe
             * pero no se resuelve todavia: seguir esa indireccion es preguntar
             * que habia guardado ahi, y eso es otro paso. */
            const analysis::ExtensionResuelta ext =
                a.valida && !a.desde_memoria.hay
                    ? analysis::resolver_extension(lig, rangos, a.extension)
                    : analysis::ExtensionResuelta{};
            for (const analysis::LigaduraAsm &ligadura : cands) {
                if (ligadura.valor == ir::IR_NO_VALUE) {
                    localizado = false;
                    break;
                }
                /* Ancho 0 = el objeto entero: lo que se dice cuando no se pudo
                 * acotar el acceso.  Con la extension, se pide por su tamano y
                 * se corre al offset donde de verdad cae. */
                const int32_t ancho =
                    ext.acotada ? (int32_t)ext.bytes() : (int32_t)0;
                /* Si la base del acceso se CARGo DE MEMORIA, la localizacion
                 * del valor no es la del acceso: falta una indireccion.
                 * `loc_of` responde donde vive el puntero -- el hueco de la
                 * pila que lo guarda --, y el `asm` escribe A DoNDE APUNTA.
                 *
                 * Tomar el hueco por el destino tenia una consecuencia que no
                 * se ve venir: el cierre de efectos filtra las escrituras a
                 * pila local porque el llamante no las observa, asi que una
                 * funcion que escribe la memoria de SU LLAMANTE a traves de un
                 * parametro salia `readonly` y `pure`.  Y con eso el llamante
                 * se queda con el valor viejo en un registro:
                 * `20_align_demostrada` daba 1 en JIT y 42 interpretado.
                 *
                 * Hasta que la indireccion se siga -- preguntar que se guardo
                 * ahi, que es otro paso --, lo correcto es no afirmar la
                 * localizacion.  Se cae al efecto generico, que dice "escribe
                 * memoria" sin decir donde: menos preciso, pero cierto.
                 *
                 * OJO: esta guarda es correcta pero NO es la que arregla el
                 * caso de `20_align_demostrada` -- comprobado, ahi no dispara,
                 * porque su base no viene marcada como cargada de memoria.  Ese
                 * sigue saliendo `readonly` y su causa esta antes: `loc_of` le
                 * da una localizacion de pila que no escapa a una escritura que
                 * va a la memoria del llamante. */
                if (a.desde_memoria.hay) {
                    localizado = false;
                    break;
                }
                AbstractLoc l = analysis::loc_of(pt, ligadura.valor, ancho);
                if (l.kind == AbstractLoc::Kind::Unknown) {
                    localizado = false;
                    break;
                }
                /* @c loc_of deja el ancho a cero cuando el offset del propio
                 * valor no es exacto; sin offset exacto no se puede correr
                 * nada, asi que la extension solo se aplica si sobrevivio. */
                if (ext.acotada && l.width > 0) l.off += ext.desde;
                if (a.escribe)
                    locs_escribe.push_back(l);
                else
                    locs_lee.push_back(l);
            }
            if (!localizado) break;
        }
    }
    if (localizado) {
        for (const AbstractLoc &l : locs_lee)
            r.effects.mem.reads.add(l);
        for (const AbstractLoc &l : locs_escribe) {
            r.effects.mem.writes.add(l);
            // Escribir por un puntero es tambien leer por el (ver el analisis).
            r.effects.mem.reads.add(l);
        }
    } else {
        if (e.reads_mem)
            r.effects.mem.reads.add({AbstractLoc::Kind::Unknown, LOC_GENERIC});
        if (e.writes_mem)
            r.effects.mem.writes.add({AbstractLoc::Kind::Unknown, LOC_GENERIC});
    }
    if (e.is_call) {
        r.effects.control.kind = ControlKind::Call;
        r.effects.may_io = true; // un call opaco puede hacer cualquier cosa
    }
    if (e.has_port_io) {
        /* Hablar con un puerto se ve desde fuera: no se puede eliminar por
         * "no hacer nada" ni mover, y descalifica el codigo como autonomo (el
         * contrato `freestanding` mira justo esta etiqueta). */
        r.effects.may_io = true;
        r.effects.tags.add(CapabilityTag::PortIO);
    }
    if (e.has_atomic) {
        r.effects.atomic.order = MemOrder::SeqCst;
        r.effects.atomic.is_fence = true;
        r.effects.tags.add(CapabilityTag::UserBarrier);
    }
    // Un asm que no toca mem, no llama y no es atomico es puro (aritmetica
    // sobre registros): efecto neutro.  Un mnemonico DESCONOCIDO no se puede
    // acotar -> efecto MAXIMO robusto (podria hacer cualquier cosa) + LAGUNA a
    // reportar.
    if (!e.known()) {
        r.effects = SemanticEffects::top();
        r.completeness = AnalysisCompleteness::Unknown;
        r.unknown_reason = UnknownReason::UnknownMnemonic;
        r.mnemonicos_desconocidos = e.unknown_mnemonics;
    } else {
        r.completeness = AnalysisCompleteness::Conservative;
    }
    return r;
}

// --------------------------------------------------------------------------
// Efecto local de UNA instruccion IR.
// --------------------------------------------------------------------------
static void add_read(SemanticEffects &e, const AbstractLoc &l) {
    e.mem.reads.add(l);
}
static void add_write(SemanticEffects &e, const AbstractLoc &l) {
    e.mem.writes.add(l);
}

const char *backend_name(Backend b) {
    switch (b) {
    case Backend::Vm: return "interprete";
    case Backend::Jit: return "JIT";
    case Backend::Aot: return "AOT nativo";
    }
    return "?";
}

/**
 * @brief Ajusta el efecto de una op a lo que hace en ESE backend.
 *
 * Una op del IR no es una instruccion: es lo que cada backend haga con ella. En
 * la VM (y en el JIT, que conserva su semantica) casi todas son una instruccion
 * de la maquina; en AOT nativo, las que dependen del runtime -- GC, monitores,
 * strings, dispatch virtual, scheduler -- se materializan como una LLAMADA a
 * libvesta_rt.  Un `strcat` no "es" una op ahi: es un `call`, con todo lo que
 * eso implica para quien lo lea (registros, orden, barrera).
 *
 * QUE necesita cada op no se decide aqui: lo dice @c aot_classify_op, que es la
 * tabla que el propio AOT usa para admitir o rechazar un programa.  Un segundo
 * criterio que dijera lo mismo con otras palabras se desincronizaria a la
 * primera op nueva.
 */
static void aplicar_backend(SemanticEffects &e, ir::IrOp op, Backend b) {
    if (b != Backend::Aot) return; // Vm y Jit comparten semantica.
    /* Un `panic` nativo no lanza: llama al hook de panico (o a `exit`) y no
     * vuelve.  No hay excepcion que capturar, asi que tampoco hay que
     * arrastrar `may_throw` por todo el cierre -- una funcion que solo puede
     * "fallar" por un panic es `nothrow` en nativo, y eso cambia lo que se
     * puede hacer con ella. */
    if (op == ir::IrOp::PANIC) {
        e.may_throw = false;
        e.control.kind = ControlKind::NoReturn;
        return;
    }
    if (aot_classify_op(op) != AotOpClass::RUNTIME_DEPENDENT) return;
    /* Solo si no cedia el control ya por si misma (una CALL sigue siendo una
     * CALL, y un RET no se convierte en llamada por pasar por el runtime). */
    if (e.control.kind == ControlKind::FallThrough)
        e.control.kind = ControlKind::Call;
}

NativeDecls
collect_native_decls(const std::vector<const ir::IrModule *> &mods) {
    NativeDecls out;
    for (const ir::IrModule *m : mods) {
        if (!m) continue;
        for (const ir::IrNativeImport &ni : m->native_imports) {
            if (!ni.effects.declared) continue;
            out.emplace(ni.lib + ":" + ni.name, &ni.effects);
        }
    }
    return out;
}

// Lo declarado para una nativa, o nullptr si nadie ha dicho nada de ella.
static const ir::IrNativeEffects *buscar_decl(const NativeDecls &d,
                                              const std::string &lib_fn) {
    auto it = d.find(lib_fn);
    return it == d.end() ? nullptr : it->second;
}

/**
 * @brief Traduce una declaracion a efectos, resolviendo la memoria en el sitio.
 *
 * La declaracion habla de ARGUMENTOS ("escribe el segundo"); aqui se convierte
 * en la localizacion concreta a la que ese argumento apunta en esta llamada,
 * con el mismo resolvedor que usan LOAD y STORE.  Por eso la declaracion se
 * puede escribir una vez y sigue siendo precisa en cada sitio.
 *
 * El ancho se deja desconocido (objeto entero): una nativa escribe un buffer,
 * no una palabra, y afinar el ancho aqui seria afirmar de mas.
 */
template <typename LocFn>
static void aplicar_decl(SemanticEffects &e, const ir::IrNativeEffects &d,
                         const std::vector<ir::IrValueId> &ops, LocFn &&loc) {
    for (uint32_t i = 0; i < ops.size() && i < 32; ++i) {
        const uint32_t bit = uint32_t(1) << i;
        if (d.reads_pointee & bit) add_read(e, loc(ops[i], 0));
        if (d.writes_pointee & bit) add_write(e, loc(ops[i], 0));
        /* Liberar es ESCRIBIR lo apuntado, y de la peor forma: lo que habia
         * deja de valer.  Se dice como escritura para que los pases que ya
         * miran eso no tengan que aprender nada nuevo; lo que APORTA de mas
         * -- que despues ya no vale -- queda apuntado en `frees_pointee` para
         * quien quiera avisar de un uso despues de liberar. */
        if (d.frees_pointee & bit) add_write(e, loc(ops[i], 0));
    }
    if (d.reads_global) add_read(e, {AbstractLoc::Kind::Global, LOC_GENERIC});
    if (d.writes_global) add_write(e, {AbstractLoc::Kind::Global, LOC_GENERIC});
    if (d.io) {
        e.may_io = true;
        e.determinism.add(DeterminismTag::ExternalObservable);
    }
    if (d.may_throw) e.may_throw = true;
    /* Los dos ejes nuevos.  Sin ellos, una nativa declarada dejaba `may_panic`
     * y `may_allocate` en falso por omision, y el motor semantico daba por
     * demostrado justo lo que nadie habia dicho. */
    if (d.may_panic) e.may_panic = true;
    if (d.allocates) e.may_allocate = true;
    /* Y los dos que el modelo ya tenia y la `extern` no sabia decir.  Van por
     * la misma razon: bajo descripcion completa, lo que nadie declara se lee
     * como demostrado, asi que si no llegan aqui una nativa que espera pasa
     * por no bloquear y una que divide por no fallar. */
    if (d.may_block) e.may_block = true;
    if (d.may_trap) e.may_trap = true;
    /* Y los refinamientos, que solo se estrechan si NADIE los ha ensanchado
     * ya: una funcion que llama a dos externas con origenes distintos tiene
     * que salir con `Any`. */
    if (d.may_throw && e.throw_origin == ir::UnwindOrigin::Any)
        e.throw_origin = d.throw_origin;
    if (d.may_panic && e.panic_origin == ir::UnwindOrigin::Any)
        e.panic_origin = d.panic_origin;
    if (d.may_trap) {
        if (d.trap_kinds == ir::TRAP_NONE)
            e.trap_kinds = ir::TRAP_NONE; // sin acotar: vale por todos
        else if (e.trap_kinds != ir::TRAP_NONE || !e.may_trap)
            e.trap_kinds =
                static_cast<ir::TrapKinds>(e.trap_kinds | d.trap_kinds);
    }
    if (d.nondeterministic)
        e.determinism.add(DeterminismTag::ExternalObservable);
}

/// Traduce UNA localizacion del callee a la memoria del llamante.  Devuelve
/// una localizacion @c Unknown cuando no se puede nombrar aqui, y quien llama
/// decide que hacer con eso -- que NO es meterla en el conjunto, porque ahi
/// absorbe todo lo demas.
static AbstractLoc instanciar_loc(const AbstractLoc &l,
                                  const std::vector<ir::IrValueId> &args,
                                  const analysis::PointsTo &pt) {
    switch (l.kind) {
    case AbstractLoc::Kind::ArgDerived: {
        /* El parametro se sustituye por el argumento REAL.  El desplazamiento
         * del callee se suma al del argumento: si el callee escribe "ocho bytes
         * mas alla de su primer parametro" y el llamante le pasa `buf`, lo que
         * se escribe son ocho bytes mas alla de `buf`. */
        if (l.id >= args.size()) break; // llamada con menos args de la cuenta.
        AbstractLoc real = analysis::loc_of(pt, args[l.id], l.width);
        if (real.kind == AbstractLoc::Kind::Unknown) return real;
        /* @c loc_of deja el ancho a cero cuando el offset del argumento no es
         * exacto; sin offset exacto no se le puede sumar nada, y lo que queda
         * es "toca ese objeto", que sigue siendo mucho mas que "toca algo". */
        if (real.width > 0) real.off += l.off;
        return real;
    }
    case AbstractLoc::Kind::Global:
    case AbstractLoc::Kind::None:
    case AbstractLoc::Kind::Unknown:
        return l; // lo global y lo desconocido significan lo mismo aqui.
    default: break;
    }
    /* Pila o monton del CALLEE: sus identificadores son suyos y aqui no
     * nombran nada.  Decir que se toca `stack#3` del llamante seria hablar de
     * otro objeto. */
    return AbstractLoc{AbstractLoc::Kind::Unknown, LOC_GENERIC};
}

/// Traduce un conjunto de localizaciones, quedandose con las que SI se pueden
/// nombrar aqui y avisando si quedo alguna fuera.
static LocSet instanciar_locset(const LocSet &s,
                                const std::vector<ir::IrValueId> &args,
                                const analysis::PointsTo &pt, bool &completo) {
    LocSet out;
    if (s.is_top) {
        // Ya venia sin acotar: no hay nada que traducir y se dice.
        completo = false;
        return out;
    }
    for (const AbstractLoc &l : s.locs) {
        const AbstractLoc t = instanciar_loc(l, args, pt);
        if (t.kind == AbstractLoc::Kind::Unknown) {
            /* No se pudo nombrar.  Meterla en el conjunto lo absorberia entero
             * -- lo desconocido es el tope del reticulo -- y con ello se
             * perderia lo que SI se sabe de las demas.  Se apunta aparte. */
            completo = false;
            continue;
        }
        out.add(t);
    }
    return out;
}

EfectoEnLlamada instanciar_en_llamada(const SemanticEffects &callee_eff,
                                      const std::vector<ir::IrValueId> &args,
                                      const analysis::PointsTo &pt) {
    EfectoEnLlamada out;
    out.lee = instanciar_locset(callee_eff.mem.reads, args, pt, out.completo);
    out.escribe =
        instanciar_locset(callee_eff.mem.writes, args, pt, out.completo);
    return out;
}

EffectAnalysisResult effects_of_instr(const ir::IrFunction &fn,
                                      const analysis::IrFacts &facts,
                                      const analysis::PointsTo &pt,
                                      const ir::IrInstr &ins,
                                      const EffectEnv &env) {
    (void)facts;            // el points-to (pt) ya se construyo con los hechos.
    EffectAnalysisResult r; // neutro Complete por defecto
    SemanticEffects &e = r.effects;
    const auto &ops = ins.operands;
    // Localizacion de un puntero-operando con el ancho del acceso actual.
    const int32_t w = access_bytes(ins.type);
    auto loc = [&](ir::IrValueId p, int32_t width) {
        return analysis::loc_of(pt, p, width);
    };

    switch (ins.op) {
    // ---- Computacion pura (sin efectos observables) ----
    case IrOp::CONST:
    case IrOp::MOV:
    case IrOp::NOP:
    case IrOp::ADD:
    case IrOp::SUB:
    case IrOp::MUL:
    case IrOp::NEG:
    case IrOp::IABS:
    case IrOp::IMIN:
    case IrOp::IMAX:
    case IrOp::IMINU:
    case IrOp::IMAXU:
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV:
    case IrOp::FNEG:
    case IrOp::FABS:
    case IrOp::FSQRT:
    case IrOp::FMIN:
    case IrOp::FMAX:
    case IrOp::FFLOOR:
    case IrOp::FCEIL:
    case IrOp::FROUND:
    case IrOp::FTRUNC:
    case IrOp::AND:
    case IrOp::OR:
    case IrOp::XOR:
    case IrOp::NOT:
    case IrOp::SHL:
    case IrOp::SHR:
    case IrOp::SAR:
    case IrOp::CLZ:
    case IrOp::CTZ:
    case IrOp::POPCNT:
    case IrOp::BYTESWAP:
    case IrOp::ROTL:
    case IrOp::ROTR:
    case IrOp::CMP_EQ:
    case IrOp::CMP_NE:
    case IrOp::CMP_LT:
    case IrOp::CMP_GT:
    case IrOp::CMP_LE:
    case IrOp::CMP_GE:
    case IrOp::CMP_ULT:
    case IrOp::CMP_UGT:
    case IrOp::CMP_ULE:
    case IrOp::CMP_UGE:
    case IrOp::FCMP_EQ:
    case IrOp::FCMP_NE:
    case IrOp::FCMP_LT:
    case IrOp::FCMP_GT:
    case IrOp::FCMP_LE:
    case IrOp::FCMP_GE:
    case IrOp::CAST:
    case IrOp::ZEXT:
    case IrOp::SEXT:
    case IrOp::TRUNC:
    case IrOp::ITOF:
    case IrOp::UITOF:
    case IrOp::FTOI:
    case IrOp::FTOUI:
    case IrOp::BITCAST:
    case IrOp::PHI:
    case IrOp::ALLOCA:
    case IrOp::GEP:
    case IrOp::STR_LIT_ADDR:
    case IrOp::LABEL_ADDR:
    case IrOp::SECTION_REF:
    case IrOp::ISNULL:
    case IrOp::INSTANCEOF:
    /* Elegir entre dos valores ya calculados no hace nada observable.  Estaba
     * sin clasificar, asi que caia al efecto MAXIMO: 12 sitios del kernel
     * quedaban como "puede hacer cualquier cosa" por un simple ternario. */
    case IrOp::SELECT:
    /* Aritmetica y nada mas.  El acarreo viaja del @c ADDC a su @c CARRYOF por
     * el grafo de valores, no por memoria, asi que aqui no hay efecto que
     * declarar (lo que SI hay es un orden que respetar, y de eso se ocupa el
     * planificador). */
    case IrOp::FMA:
    case IrOp::ADDC:
    case IrOp::SUBB:
    case IrOp::CARRYOF:
    // Conversiones de puntero/handle: solo calculan una direccion (el
    // load/store real es una op aparte); sin efecto observable propio.
    case IrOp::GCDEREF_IR:
    case IrOp::GC_DEREF_HOST:
    case IrOp::GC_HANDLE_FOR_PTR:
    // Metadata de depuracion: no afecta la semantica de datos del programa.
    case IrOp::SETMETHDBG:
        break; // efecto neutro

    // ---- Division: puede atrapar (div-by-zero) ----
    case IrOp::DIV:
    case IrOp::MOD: e.may_trap = true; break;

    // ---- Memoria (localizacion precisa: raiz + offset + ancho del acceso)
    // ----
    case IrOp::LOAD:
        if (!ops.empty()) add_read(e, loc(ops[0], w));
        break;
    case IrOp::STORE:
        if (ops.size() >= 2) add_write(e, loc(ops[1], w));
        break;
    case IrOp::ARRAY_LOAD:
        if (!ops.empty()) add_read(e, loc(ops[0], w));
        break;
    case IrOp::ARRAY_STORE:
        if (!ops.empty()) add_write(e, loc(ops[0], w));
        break;
    case IrOp::GETFIELD:
        if (!ops.empty()) add_read(e, loc(ops[0], w));
        break;
    case IrOp::SETFIELD:
    case IrOp::GCWB_IR:
        if (!ops.empty()) add_write(e, loc(ops[0], w));
        break;
    case IrOp::GETSTATIC:
        add_read(e, {AbstractLoc::Kind::Global, LOC_GENERIC});
        break;
    case IrOp::SETSTATIC:
        add_write(e, {AbstractLoc::Kind::Global, LOC_GENERIC});
        break;
    case IrOp::ARRAY_LEN:
    case IrOp::STRLEN:
    case IrOp::STRGETBYTES:
    case IrOp::STRHASH:
    /* Comparar dos cadenas LEE las dos y no escribe nada.  Estaba sin
     * clasificar, asi que caia al efecto maximo: 25 sitios de la stdlib
     * quedaban como "puede hacer cualquier cosa" por un `==` entre cadenas. */
    case IrOp::STRCMP:
    // STRRAW: devuelve un host_ptr al buffer de datos del StringObject -> LEE
    // el objeto (cabecera+datos) para calcular el puntero; no
    // escribe/aloca/lanza. Una escritura POSTERIOR via el puntero devuelto es
    // un STORE aparte (modelado).  Sin esto, strraw subia a top() (laguna
    // modelable).
    case IrOp::STRRAW:
        // leen la cabecera del objeto (ancho desconocido = objeto entero).
        if (!ops.empty()) add_read(e, loc(ops[0], 0));
        break;
    // MEMCPY + ops VECTORIALES: delegan en el vocabulario UNICO memory_access
    // (memcpy NO es opaco; los VEC ESCRIBEN memoria -- antes VEC_UNOP/BINOP/FMA
    // estaban mal clasificados como PUROS, lo que podia clasificar una funcion
    // que solo hace stores vectoriales como "pura" -> unsound en las
    // relajaciones pure-call).  opaco -> top; VEC_BCAST no toca memoria.
    // La lista tiene que ser la de ir::is_vec_op AL COMPLETO: la que faltaba,
    // VEC_FMA_S, caia al `default` y salia con su efecto MAXIMO -- correcto,
    // pero anotado como laguna del motor y sin precision ninguna, pese a que
    // memory_access si sabe modelarla.
    case IrOp::MEMCPY:
    case IrOp::MEMSET:
    case IrOp::VEC_UNOP:
    case IrOp::VEC_BINOP:
    case IrOp::VEC_BINOP_S:
    case IrOp::VEC_FMA:
    case IrOp::VEC_FMA_S:
    case IrOp::VEC_BCAST:
    case IrOp::VEC_ACC_ZERO:
    case IrOp::VEC_ACC_ADD:
    case IrOp::VEC_ACC_FMA:
    case IrOp::VEC_ACC_STORE:
    case IrOp::VEC_ACC_COMBINE: {
        const analysis::MemoryAccess ma = analysis::memory_access(ins, pt);
        if (ma.touches) {
            if (ma.opaque) {
                if (ma.is_load)
                    add_read(e, {AbstractLoc::Kind::Unknown, LOC_GENERIC});
                if (ma.is_store)
                    add_write(e, {AbstractLoc::Kind::Unknown, LOC_GENERIC});
            } else {
                for (const auto &r : ma.reads)
                    add_read(e, r);
                for (const auto &w : ma.writes)
                    add_write(e, w);
            }
        }
        break;
    }

    // ---- Asignacion de memoria (aloca heap) ----
    case IrOp::RAW_ALLOC:
    case IrOp::GC_ALLOC:
    case IrOp::GC_ALLOCP:
    case IrOp::NEWOBJ:
    case IrOp::ARRAY_ALLOC:
    case IrOp::MAKE_CLOSURE:
    case IrOp::STRMAKE:
    case IrOp::STRCAT:
    case IrOp::STRCONV:
    case IrOp::STRSLICE:
    case IrOp::STRFLAT:
    case IrOp::STRINTERN:
    case IrOp::STRRESERVE:
    case IrOp::MAKE_VARIANT:
    case IrOp::SPECIALIZE:
    case IrOp::FUTURE: e.may_allocate = true; break;

    /* ---- Liberacion: invalida LO QUE LIBERA, no toda la memoria ----
     *
     * Liberar un bloque invalida ese bloque y cuanto apunte dentro de el;
     * lo demas sigue igual de valido que antes.  Y cual es se sabe: el
     * operando es el puntero, y el mismo resolvedor que usan LOAD y STORE
     * dice a que apunta.  Decir "escribe en cualquier sitio" convertia cada
     * `free` -- y cada salida de ambito de un `unique<T>` -- en una barrera
     * para todo lo que hubiera alrededor.
     *
     * Que otros punteros al MISMO objeto queden invalidos lo cubre la propia
     * localizacion: comparten raiz, asi que cualquiera que pregunte por ellos
     * ve el conflicto.  Y si no se puede resolver, se vuelve a lo de antes. */
    case IrOp::RAW_FREE:
    case IrOp::SMARTPTR_FREE:
        add_write(e, ops.empty()
                         ? AbstractLoc{AbstractLoc::Kind::Unknown, LOC_GENERIC}
                         : loc(ops[0], 0 /*todo el objeto*/));
        break;
    case IrOp::GC_COLLECT:
    case IrOp::GC_FINALIZE_ALL:
        add_write(e, {AbstractLoc::Kind::Unknown, LOC_GENERIC});
        break;

    // ---- Excepciones ----
    case IrOp::THROW:
    case IrOp::RETHROW:
        e.may_throw = true;
        e.control.kind = ControlKind::Throw;
        break;
    /* `panic` no baja igual en todas partes, y la diferencia importa: en la VM
     * lanza un FatalError, que se puede CAPTURAR con `try`/`catch`, asi que hay
     * camino de vuelta; en nativo es el hook de panico (o `exit`) y de ahi no
     * se vuelve.  Decir "lanza" en los dos casos hace creer que un `catch` de
     * mas arriba lo recogera, y en nativo no hay tal.  Ver aplicar_backend. */
    case IrOp::PANIC:
        e.may_throw = true; // en la VM SI hay excepcion que capturar
        e.may_panic = true;
        e.control.kind = ControlKind::Throw;
        break;
    case IrOp::UNWRAP:    // NullPointerException si null
    case IrOp::CHECKCAST: // ClassCastException
        e.may_throw = true;
        break;

    // ---- Control ----
    case IrOp::RET: e.control.kind = ControlKind::Return; break;
    case IrOp::BR:
    case IrOp::BR_COND:
    case IrOp::SWITCH_DENSE:
    case IrOp::MATCH_VARIANT: e.control.kind = ControlKind::Branch; break;
    case IrOp::UNREACHABLE: e.control.kind = ControlKind::NoReturn; break;

    // ---- Llamadas.  El efecto LOCAL es 'transfiere control'; el efecto del
    // callee entra por el cierre (Fase 2).  Las dinamicas/nativas son opacas.
    // ----
    case IrOp::CALL:
    case IrOp::TAILCALL: e.control.kind = ControlKind::Call; break;
    case IrOp::CALLVIRT:
    case IrOp::CALLM:
    case IrOp::CALLITF:
    case IrOp::CALLCLOSURE:
        e.control.kind = ControlKind::Call;
        r.completeness = AnalysisCompleteness::Conservative; // callee dinamico
        r.unknown_reason = UnknownReason::DynamicDispatch;
        break;
    case IrOp::CALLIND:
        e.control.kind = ControlKind::Call;
        r.completeness = AnalysisCompleteness::Conservative;
        r.unknown_reason = UnknownReason::Indirect;
        break;
    case IrOp::CALLN: {
        /* Una llamada NATIVA no es opaca por definicion.  Su efecto LOCAL es el
         * de cualquier llamada -- ceder el control --; lo que hace el destino
         * lo pone el cierre interprocedural, que lo busca por nombre y lo
         * ANALIZA si esta en el programa.  Solo cuando el destino no aparece,
         * el cierre sube al efecto maximo y lo nombra en el informe.
         *
         * Antes se daba por caja negra aqui mismo, con lo que daba igual que el
         * destino estuviera delante: nadie llegaba a mirarlo. */
        e.control.kind = ControlKind::Call;
        /* Sin nombre no hay nada que resolver ni a quien preguntar: eso si es
         * opaco de verdad, y se dice aqui mismo con su motivo.  El caso con
         * nombre lo resuelve el cierre, que es quien sabe si el destino esta en
         * el programa. */
        if (ins.func_name.empty()) {
            e = SemanticEffects::top();
            r.completeness = AnalysisCompleteness::Conservative;
            r.unknown_reason = UnknownReason::UnknownFFI;
            break;
        }
        /* Y si el destino no esta pero alguien DIJO lo que hace, se usa.  La
         * declaracion habla de argumentos ("escribe el segundo"), y es aqui --
         * en el sitio de llamada -- donde eso se puede convertir en memoria
         * concreta: el mismo resolvedor que usan LOAD y STORE. */
        const ir::IrNativeEffects *d =
            env.decls ? buscar_decl(*env.decls, ins.func_name) : nullptr;
        if (d) aplicar_decl(e, *d, ops, loc);
        break;
    }

    // ---- Concurrencia ----
    case IrOp::AWAIT:
    case IrOp::MONENTER:
    case IrOp::MONWAIT:
    case IrOp::MSGRECV: e.may_block = true; break;
    case IrOp::MONEXIT: e.atomic.order = MemOrder::Release; break;
    case IrOp::MSGSEND:
    case IrOp::FULFILL:
    case IrOp::REJECT:
    case IrOp::FULFILL_HLT:
        e.may_io = true; // comunicacion observable
        break;
    case IrOp::SPAWN:
    case IrOp::SPAWN_ARGS:
    case IrOp::RSPAWN:
        e.may_allocate = true; // crea proceso
        e.may_io = true;
        break;
    case IrOp::YIELD:
    case IrOp::RESUME: e.control.kind = ControlKind::Suspend; break;

    // ---- Estado del proceso / entorno (no determinista) ----
    case IrOp::GETPROC:
    case IrOp::GETVM:
    case IrOp::READ_VM_REG:
        e.determinism.add(DeterminismTag::ExternalObservable);
        break;

    // ---- I/O / carga dinamica ----
    case IrOp::DLOPEN:
    case IrOp::DLSYM:
    case IrOp::MOD_LOAD:
        e.may_io = true;
        r.completeness = AnalysisCompleteness::Conservative;
        break;

    /* ---- Atomicas ----
     * Sin clasificar caian al efecto MAXIMO, lo que dejaba a `std.atomic`,
     * `chan`, `mutex` y `pool` -- justo el nucleo de la concurrencia -- como
     * "puede hacer cualquier cosa".  Se sabe perfectamente lo que hacen: tocan
     * la localizacion que se les pasa, y ORDENAN (por eso son atomicas). */
    case IrOp::ATOMIC_LD:
        if (!ops.empty()) add_read(e, loc(ops[0], w));
        e.atomic.order = MemOrder::SeqCst;
        break;
    case IrOp::ATOMIC_ST:
        if (!ops.empty()) add_write(e, loc(ops[0], w));
        e.atomic.order = MemOrder::SeqCst;
        break;
    case IrOp::ATOMIC_CAS:
    case IrOp::ATOMIC_ADD:
        // Leen y escriben la MISMA localizacion, en un solo paso indivisible.
        if (!ops.empty()) {
            add_read(e, loc(ops[0], w));
            add_write(e, loc(ops[0], w));
        }
        e.atomic.order = MemOrder::SeqCst;
        break;

    // ---- Reflexion / registro de clases (muta el ClassRegistry) ----
    case IrOp::DEFCLASS:
    case IrOp::DEFFIELD:
    case IrOp::DEFMETHOD:
    case IrOp::ADDADVICE:
        add_write(e, {AbstractLoc::Kind::Global, LOC_GENERIC});
        e.may_allocate = true;
        break;
    case IrOp::FINDCLASS:
    case IrOp::FINDMETHOD:
        add_read(e, {AbstractLoc::Kind::Global, LOC_GENERIC});
        break;

    // ---- Residuo de asm OPACO ----
    case IrOp::INLINE_ASM:
    case IrOp::ASM_MICRO: return opaque_asm_effects(fn, pt, ins, env);

    default:
        // Op no clasificada -> efecto MAXIMO (top): robusto y completo, cubre
        // CUALQUIER cosa que la op pueda hacer.  Nunca afirma de menos.  Marca
        // UnmodeledOp: es una LAGUNA del motor (deberiamos clasificar esta op
        // para ganar precision), NO una opacidad fundamental.
        e = SemanticEffects::top();
        r.completeness = AnalysisCompleteness::Conservative;
        r.unknown_reason = UnknownReason::UnmodeledOp;
        break;
    }
    aplicar_backend(e, ins.op, env.backend);
    return r;
}

// --------------------------------------------------------------------------
// Agregado local de una funcion: seq dentro de bloque, join entre bloques.
// --------------------------------------------------------------------------
EffectAnalysisResult function_local_effects(const ir::IrFunction &fn,
                                            EffectGaps *gaps,
                                            const EffectEnv &env) {
    analysis::IrFacts facts = analysis::build_ir_facts(fn);
    analysis::PointsTo pt = analysis::compute_points_to(fn, facts);
    EffectAnalysisResult acc;
    bool first_block = true;
    AnalysisCompleteness worst = AnalysisCompleteness::Complete;

    for (const ir::IrBlock &b : fn.blocks) {
        SemanticEffects blk = SemanticEffects::none();
        bool first_instr = true;
        for (const ir::IrInstr &in : b.instrs) {
            EffectAnalysisResult r = effects_of_instr(fn, facts, pt, in, env);
            if (uint8_t(r.completeness) > uint8_t(worst))
                worst = r.completeness;
            // Registrar la laguna (si la hubo) para el reporte de cobertura.
            if (gaps && r.completeness != AnalysisCompleteness::Complete &&
                r.unknown_reason != UnknownReason::None) {
                gaps->record(static_cast<int>(in.op), r.unknown_reason);
                for (const std::string &m : r.mnemonicos_desconocidos)
                    gaps->record_mnemonico(m);
                if (!r.nativa_sin_declarar.empty())
                    gaps->record_nativa(r.nativa_sin_declarar);
            }
            blk = first_instr ? r.effects : seq(blk, r.effects);
            first_instr = false;
        }
        acc.effects = first_block ? blk : join(acc.effects, blk);
        first_block = false;
    }
    acc.completeness = worst;
    return acc;
}

} // namespace effects
} // namespace analysis
