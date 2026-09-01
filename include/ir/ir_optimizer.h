/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir_optimizer.h
 * @brief Optimizador de la SSA IR de VestaVM con niveles O0-O3.
 *
 * Catalogo completo de pases implementados.  Cada nivel activa un
 * subconjunto acumulativo, ejecutado hasta punto fijo (max 8 iter) para
 * capturar oportunidades encadenadas (p.ej. un DCE expone CSE nuevo, que
 * a su vez expone simplificaciones algebraicas, etc.).
 *
 * Pases por nivel:
 *
 *   O0: ninguno (util para depuracion: el bytecode emitido es 1:1 con el
 *       IR generado por el frontend, sin reordenar ni eliminar nada).
 *
 *   O1: pases puramente locales y baratos (lineales en numero de instrs):
 *         - ir_pass_dce             elimina instrs puras sin usos
 *         - ir_pass_copy_prop       propaga MOVs trivials
 *         - ir_pass_simplify        identidades algebraicas + cast-fold +
 * phi-fold
 *         - ir_pass_dead_alloc_elim purga news cuyo resultado no se usa
 *
 *   O2: añade analisis de flujo + transformaciones globales:
 *         - ir_pass_const_fold      pliega aritmetica con operandos constantes
 *         - ir_pass_unreachable     poda bloques no alcanzables desde entry
 *         - ir_pass_strength_reduction  MUL/DIV/MOD por 2^k -> SHL/SHR/AND
 *         - ir_pass_reassoc         (x+c1)+c2 -> x+(c1+c2)  (y otras assoc ops)
 *         - ir_pass_tailcall        CALL+RET -> TAILCALL (libera frame OOP)
 *         - ir_pass_licm            sube invariantes fuera del loop
 *         - ir_pass_load_narrow     elide sign-extend redundante tras LOAD
 * i8/16/32
 *         - ir_pass_dse             elimina STOREs consecutivos a misma
 * direccion
 *         - ir_pass_devirt_monomorphic  CALLVIRT con clase conocida -> CALL
 * directo
 *
 *   O3: añade pases de duplicacion / reordenacion mas agresivos:
 *         - ir_pass_cse             dedup de subexpresiones comunes
 * (intra-block)
 *         - ir_pass_const_cse_entry hoist de CONSTs a entry block
 *         - ir_pass_inline          inlining cross-function (modulo)
 *         - ir_pass_schedule        list scheduling para exponer ILP al host
 * CPU
 *
 * Todos los pases operan sobre IrFunction o IrModule en memoria.  No
 * generan texto ni bytecode; son transformaciones puras sobre la IR.
 * Cada pase preserva la propiedad SSA (asignacion unica) salvo cuando
 * elimina instrucciones completas (esto es seguro porque sus destinos
 * dejan de ser usados).
 *
 * Por que un loop a punto fijo:  los pases no son independientes.  Un
 * DCE elimina una mul cuyo resultado no se usaba; eso expone un CONST
 * antes vivo (porque alimentaba la mul) que ahora tambien es dead, y
 * que solo la siguiente iteracion de DCE captura.  Empiricamente 3-4
 * iteraciones cubren ~95% de los casos; el limite de 8 evita patologias
 * en programas degenerados sin sacrificar tiempo de compilacion notable.
 */

#ifndef IR_OPTIMIZER_H
#define IR_OPTIMIZER_H

#include "analysis/effects/ir_effects.h"
/* Los hechos que el DSE recibe ya calculados (ver @c HechosDeAsmParaDse): se
 * pasan por referencia, asi que hacen falta sus definiciones. */
#include "analysis/facts/asm_bindings.h"
#include "analysis/facts/ir_facts.h"
#include "analysis/facts/value_range.h"
#include "ir/ssa_ir.h"

#include <string>
#include <unordered_set>

namespace analysis {
struct PointsTo; // resolvedor points-to compartido
                 // (analysis/memory/points_to.h)
} // namespace analysis

namespace ir {

/**
 * @brief Nivel de optimizacion de la SSA IR.
 */
enum class OptLevel : int {
    O0 = 0, ///< sin pases; emite IR tal cual del frontend (depuracion).
    O1 = 1, ///< pases locales baratos: DCE, copy-prop, simplify, dead-alloc.
    O2 = 2, ///< O1 + global: const-fold, unreachable, SR, reassoc, tailcall,
            ///<       LICM, load-narrow, DSE, devirt monomorfico.
    O3 = 3, ///< O2 + agresivos: CSE local, const-CSE-entry, inline cross-fn,
            ///<       list scheduling (expone ILP al host CPU / JIT).
};

/**
 * @brief Convierte un entero 0-3 al nivel de optimizacion correspondiente.
 * @param n Nivel numerico (se satura a O3 si n>3).
 * @return OptLevel equivalente.
 */
inline OptLevel opt_level_from_int(int n) {
    if (n <= 0) return OptLevel::O0;
    if (n == 1) return OptLevel::O1;
    if (n == 2) return OptLevel::O2;
    return OptLevel::O3;
}

// =========================================================================
//  Interfaz publica principal
// =========================================================================

/**
 * @brief Aplica todos los pases de optimizacion del nivel indicado al modulo.
 *
 * Ejecuta los pases hasta punto fijo o hasta un maximo de 8 iteraciones para
 * capturar oportunidades encadenadas (p.ej., un DCE puede exponer nuevo CSE).
 *
 * @param mod   Modulo IR a optimizar (modificado en su lugar).
 * @param level Nivel de optimizacion.
 * @param allow_inline @c false para NO expandir llamadas (inline).  Lo usa el
 *        modo --analyze: el coste PARCIAL es una propiedad del CUERPO ESCRITO
 *        por el programador, estable entre compilaciones; si el inline lo
 *        modificase, dependeria de decisiones del optimizador (-O0 vs -O3
 *        darian partiales distintos).  El coste interprocedural (TOTAL) lo
 *        compone el analizador via el callgraph, no via inline.  Default @c
 *        true: JIT/AOT/interp inlinan normalmente.
 */
/**
 * @brief Lo que costo cada pase del optimizador, y cuantas veces corrio.
 *
 * El tiempo de "optimizar" es un solo numero y con el no se puede arreglar
 * nada: un pase que se lleva el 90 % se lee igual que veinte que se reparten.
 * Esto lo abre por pase, que es la unidad en la que se puede actuar.
 *
 * Se acumula SIEMPRE (un reloj por pase es despreciable al lado del pase) y lo
 * consulta quien vaya a ensenarlo.
 */
struct TiempoPase {
    const char *nombre = "?";
    long long us = 0;    ///< tiempo acumulado.
    long long veces = 0; ///< llamadas (el punto fijo repite pasadas).
};

/// Vueltas del punto fijo, SUMADAS sobre todos los modulos.  El bucle corta
/// solo cuando ninguna funcion cambia, asi que este numero es lo que el codigo
/// PIDIO, no una constante: hay programas que convergen en dos vueltas y otros
/// que necesitan diez.
long long &vueltas_punto_fijo();

/**
 * @brief Veces que el punto fijo se quedo SIN converger, agotando el tope.
 *
 * El tope existe para que un par de pases que se deshagan el trabajo no cuelgue
 * al compilador; no es un mando para regular cuanto se optimiza.  Cuando se
 * toca, el optimizador se rinde a medias y emite codigo peor -- y hasta que
 * esto se conto, lo hacia EN SILENCIO: el compilador terminaba bien, el
 * programa funcionaba, y nadie podia saber que le faltaban vueltas.  Lo
 * descubrio una diferencia de 21 KB entre dos binarios que debian ser iguales.
 *
 * Distinto de cero significa que hay que mirarlo, no que haya que subir el
 * tope.
 */
long long &fixpoint_truncations();

/// Visitas a una funcion (vueltas x funciones, sumado sobre los modulos).  Es
/// el numero con el que TIENE que cuadrar la cuenta de llamadas de un pase que
/// corra una vez por funcion; si no cuadra, el contador esta mal.
long long &visitas_a_funcion();

/**
 * @brief Lo que costo un pase EN UNA FUNCION concreta.
 *
 * El reparto por pase dice cual es caro; este dice si lo es por igual en todas
 * o por una sola.  Son dos averias distintas: un pase caro repartido se
 * arregla haciendolo mas barato, y uno caro concentrado en la funcion mas
 * grande se arregla mirando como crece con el tamano.  Sin separarlas se
 * ataca a ciegas.
 */
struct TiempoPaseFuncion {
    const char *pase = "?";
    std::string funcion;
    long long us = 0;
    long long veces = 0;
    long long instrucciones = 0; ///< tamano de la funcion, para ver la curva.
};

/// Los pares (pase, funcion) mas caros primero.
std::vector<TiempoPaseFuncion> tiempos_por_funcion();

/// Los pases que han corrido, del mas caro al mas barato.
std::vector<TiempoPase> tiempos_de_pases();

/// Pone a cero el acumulador (una compilacion no debe heredar el reparto de
/// otra: se llama al empezar cada @ref ir_optimize del modulo raiz).
void reiniciar_tiempos_de_pases();

void ir_optimize(IrModule &mod, OptLevel level, bool allow_inline = true);

// =========================================================================
//  Pases individuales (se pueden invocar directamente si se desea)
// =========================================================================

/**
 * @brief Pase DCE: elimina instrucciones cuyo resultado nunca se usa.
 *
 * Elimina lo que no tiene efecto observable.  "Sin efecto" lo decide el modelo
 * unico de efectos, no una lista de opcodes: una llamada nativa DECLARADA que
 * solo escribe en un buffer que nadie lee tampoco tiene efecto, y una que no
 * declara nada sigue siendo opaca y se conserva.
 *
 * @param fn    Funcion a optimizar.
 * @param decls Lo declarado sobre las nativas del programa, o @c nullptr si no
 *              se sabe nada de ellas (entonces toda CALLN es opaca).
 * @return true si se elimino al menos una instruccion.
 */
/**
 * @brief Lo que el modelo de efectos contesto sobre cada instruccion de una
 *        funcion.
 *
 * Preguntar por los efectos de una instruccion cuesta ~107 us medidos, y el
 * eliminador de codigo muerto lo pregunta una vez por instruccion en cada
 * pasada: sobre una funcion de 1740 instrucciones y dieciseis pasadas, eso es
 * casi todo el tiempo de compilar.  Pero la respuesta NO cambia mientras la
 * funcion no cambie, asi que se guarda.
 *
 * Es una CACHE, no un buffer que se reutiliza: cada respuesta es inmutable
 * mientras vale, va indexada por su instruccion, y se tira ENTERA en cuanto
 * algo toca la funcion.  La diferencia importa -- un buffer reciclado se lo
 * pisa el siguiente que pregunte.
 *
 * Y NO sustituye al modelo: lo que guarda es lo que el modelo contesto.  Si el
 * modelo se afina manana, esto contesta lo afinado.
 */
struct CacheEfectosDce {
    /// Instrucciones que tenia la funcion al llenarse.  Si cambia, no vale.
    size_t n = 0;
    /**
     * @brief Para QUE objetivo se lleno.
     *
     * La respuesta del modelo NO es la misma en todos: compilando a nativo, un
     * `panic` no lanza excepcion sino que no vuelve, y varias operaciones pasan
     * a ceder el control porque van por el runtime.  Y el analisis de un bloque
     * de asm lee su texto con la tabla de SU arquitectura -- las mismas letras
     * dicen otra cosa en x86 que en ARM.
     *
     * Guardarlo es lo que impide servir la respuesta de otro objetivo.  Es la
     * misma leccion del fichero de hechos: lo que se guarda tiene que decir
     * DONDE vale, o acaba contestando donde no debe.
     */
    int backend = -1;
    std::string isa;
    /// Por indice lineal: -1 sin preguntar, 0 conservar, 1 se puede quitar.
    std::vector<int8_t> resp;

    void invalidar() {
        n = 0;
        backend = -1;
        isa.clear();
        resp.clear();
    }
};

/**
 * @note Reconstruye los hechos y el points-to de la funcion en CADA llamada.
 *       Prestarselos ya calculados es SEGURO desde el sello de version, pero
 *       MEDIDO no compensa: sube el optimizador un 4 % porque lo que cuesta
 *       aqui no es el def-use sino el calculo de rangos que viene despues.  El
 *       detalle, con los numeros, esta en el cuerpo del pase.
 */
bool ir_pass_dce(IrFunction &fn,
                 const analysis::effects::NativeDecls *decls = nullptr,
                 const analysis::AsmBindingFacts *asm_bindings = nullptr,
                 CacheEfectosDce *cache = nullptr);

/**
 * @brief Elision comptime de UNWRAP cuando el operando es provably non-null
 *        (CONST!=0, ALLOCA, STR_LIT_ADDR, LABEL_ADDR, o resultado de UNWRAP).
 *        Convierte el UNWRAP en MOV -> copy_prop/DCE lo eliminan (cero codigo).
 */
bool ir_pass_elide_unwrap(IrFunction &fn);

/**
 * @brief Pase Dead Alloc Elimination.
 *
 * Elimina CALLs a funciones synthetic @c __new_<ClassName> (helpers de
 * allocacion emitidos por el frontend Vesta) y otros allocators puros
 * (@c vrt_newobj, @c vrt_newobj_handle, @c vrt_register_alloc) cuyo
 * resultado nunca se usa.
 *
 * El frontend Vesta emite @c new ClassName() como un @c call ptr
 * @c @__new_ClassName().  Si el SSA value resultante no se usa
 * (e.g. @c Calculadora a = new Calculadora(); return 0; donde @c a
 * nunca se referencia), eliminar la CALL es semanticamente seguro
 * para Vesta (solo presion GC adicional como efecto observable).
 *
 * Coste eliminado: 1 alloc completa (~10 ns con PtrHandleMap) por
 * iteracion del loop.  Para benches como @c 100_reflection_full con
 * 30M iteraciones de alloc descartada, el speedup es ~10x.
 *
 * @param fn Funcion a optimizar.
 * @return true si se elimino al menos una CALL.
 */
bool ir_pass_dead_alloc_elim(IrFunction &fn);

/**
 * @brief Quita los huecos de PILA que nadie lee, y lo que se escribia dentro.
 *
 * Tras promover una reserva del monton a la pila, el valor queda en un hueco y
 * su direccion en otro.  Si nadie los lee -- porque la lectura ya se resolvio
 * en el sitio -- solo quedan escrituras que no ve nadie.
 *
 * Lo que las mantenia vivas era la LIBERACION, que se conserva a proposito al
 * promover y los backends quitan porque soltar pila no es nada; aqui no cuenta
 * como leer.  Tampoco cuenta escribir DENTRO.  Si cuenta guardar la DIRECCION
 * de un hueco en otro, y solo si aquel vive: de ahi el punto fijo.
 *
 * @param fn Funcion a limpiar (se modifica en el sitio).
 * @return true si se quito algo.
 */
bool ir_pass_dead_stack_slot_elim(IrFunction &fn);

/**
 * @brief Promueve ALLOCAs cuyo ptr fluye a CALLN a host stack.
 *
 *  D.jit-mem-model AUTO-PROMOTE: detecta `&local` que llega a
 * funciones nativas (CALLN).  Marca el dst del ALLOCA como
 * `is_host_ptr=true`, lo que hace que el JIT lo emita en host stack
 * (en lugar de VM-stack) -- el ptr resultante es genuino dereferenciable
 * directamente por code C nativo.
 *
 * Permite sintaxis C-style sin anotaciones:
 *
 *     u8[1024] buf;
 *     ReadFile(handle, &buf[0], 1024, ...);
 *
 * @return true si se promociono alguna ALLOCA.
 */
bool ir_pass_promote_callned_allocas(IrFunction &fn);

/**
 * @brief Sprint string-perf-8: promueve ALLOCAs LOCALES (no escapan a
 *        CALL/RET/THROW/STORE-de-ptr) a `host_alloca=true`.
 *
 * Permite que el JIT emita los LOAD/STORE derivados como `mov` nativo
 * directo (1 instr) en lugar del inline page cache check (~10 instr).
 *
 * Caso tipico: struct value-type local con field access en hot loop.
 * Speedup esperado en bench_struct_field: 5x (150ms -> 30ms en JIT).
 *
 * @return true si se promociono alguna ALLOCA.
 */
// @c force_all=true (bare AOT): promueve TODAS las ALLOCAs a host_alloca,
// escapen o no.  En bare nativo no hay VM stack (rbx no es un ProcessVM*),
// asi que un ALLOCA_VM ([rbx+off]) corrompe.  Cualquier local debe vivir en
// la pila nativa.  Default (false): solo promueve las que no escapan (JIT/VM).
bool ir_pass_promote_local_allocas(IrFunction &fn, bool force_all = false);

/**
 * @brief SROA/mem2reg de los locales de pila: de memoria a REGISTRO (SSA).
 *
 * Lo llamaba solo el optimizador, pero no es una optimizacion en el sentido de
 * hacer el programa mas rapido: es CONSTRUCCION DE SSA.  No quita un bucle ni
 * cambia cuantas vueltas da; pone el programa en la forma en la que los
 * analisis hablan -- con PHIs en las cabeceras --.
 *
 * Por eso se declara: el ASA lo necesita para que su foto de ANTES de
 * optimizar sea analizable.  Sin el, el contador de un `for` vive en un
 * `alloca` y se lee con un `load` en cada vuelta, asi que no hay PHI, y sin
 * PHI no hay variable de induccion que encontrar.
 *
 * @return true si promociono algo.
 */
bool ir_pass_sroa_stack_structs(IrFunction &fn);

/**
 * @brief Propaga @c is_host_ptr por las cadenas de aritmetica de punteros.
 *
 * Recorre ADD/SUB/casts/PHI marcando el destino como host cuando alguno de sus
 * operandos ya lo es, hasta punto fijo.  Complementa a
 * @c ir_pass_promote_local_allocas, cuya propagacion interna solo cubre las
 * ALLOCAs que ese mismo pase promueve: las que marca el lowering (locales
 * address-taken) necesitan esta.  Sin ella, `&p.campo` con offset != 0 pierde
 * la naturaleza host y emite `mov` (VM) en lugar de `movh`.
 *
 * Solo añade el flag (nunca lo quita), asi que es idempotente.
 *
 * @param fn Funcion IR a procesar (se ignora si es nativa).
 * @return true si marco algun value nuevo.
 */
bool ir_pass_propagate_host_ptr(IrFunction &fn);

/**
 * @brief Promociona patrones `malloc(N) + ... + free(p)` locales sin
 *        escape a `ALLOCA host_alloca`.
 *
 * Cuando una funcion Vesta usa @c malloc/free localmente (sin escape via
 * return ni stores a memoria GC), el coste del allocator (~200-500 ns
 * por call) en loops domina el wall-time.  Esta pasada convierte el
 * patron a `sub rsp, N` (1 instr, ~1 ns) y elimina el RAW_FREE
 * correspondiente (el stack se libera al RET).
 *
 * Criterios:
 *   1. RAW_ALLOC con @c operands[0] siendo CONST.
 *   2. CONST.size <= 65536 bytes (no llenar stack con bloques gigantes).
 *   3. El dst NO escapa (no llega a RETURN ni a stores a memoria GC).
 *   4. Existe un RAW_FREE que recibe el dst (o derivado).
 *
 * @return true si se promociono algun RAW_ALLOC.
 */
bool ir_pass_promote_local_raw_alloc(IrFunction &fn);

/**
 * @brief AOT/native_poo: promueve el env de una closure de HEAP
 *        (GC_ALLOC/RAW_ALLOC) a STACK (ALLOCA) cuando no escapa del frame.
 *
 * Closure-aware: relaja el escape-check para `STORE R,closure_slot[+k]` (slot
 * ALLOCA local) y `CALLCLOSURE env=R` (uso sincrono), que el pase generico
 * marca como escape.  Conservador: cualquier uso desconocido -> no promueve
 * (peor caso = rechazo en bare, NUNCA use-after-free).  Habilita closures
 * capturantes que escapan (p.ej. tras inlinar la factoria) SIN heap ni leak.
 * @return true si promociono algun env.
 */
bool ir_pass_promote_closure_env(IrFunction &fn);

/**
 * @brief Inserta el RAW_FREE del env de una closure que escapa cross-function
 *        (opcion 1: heap + RAII determinista), solo AOT/bare (native_poo).
 *
 * Corre a NIVEL MODULO tras inline+promote (asi solo ve los envs que
 * sobrevivieron como RAW_ALLOC etiquetado "__closure_env" -- escapes
 * cross-function reales; los no-escapantes ya estan en stack via promote).
 *
 * Para cada funcion "yielder" (crea un env que escapa via RET, o reenvia el
 * resultado de otra yielder), busca el DUENO terminal: el consumidor que liga
 * el resultado a un local que NO se reenvia ni se deja escapar.  En ese dueno
 * inserta `ep = LOAD [closure+8]; RAW_FREE ep` en cada RET (RAW_FREE(0) es
 * no-op -> seguro para closures sin capturas).  Si TODA la cadena tiene dueno
 * limpio, conserva el RAW_ALLOC (bare-compatible) y le quita el tag.  Si algun
 * env no tiene dueno limpio, REVIERTE su RAW_ALLOC a GC_ALLOC -> aot_analyze
 * lo rechaza limpio (REGLA: nunca leak).  Conservador: ante cualquier duda,
 * revierte (rechazo) en vez de arriesgar un leak/UAF.
 *
 * @param mod Modulo a transformar in-place.
 * @return true si inserto algun free o revirtio algun alloc.
 */
bool ir_pass_own_closure_envs(IrModule &mod);

/**
 * @brief Pliega los @c STRCAT cuyas dos partes se conocen al compilar.
 *
 * `"aaa" + "bbb"` en la MISMA expresion ya lo pliega el frontend.  Este pase
 * cubre lo que aquel no puede ver -- que las partes lleguen por VARIABLES:
 *
 *     string a = "aaa";
 *     string b = "bbb";
 *     string c = a + b;      // -> c = "aaabbb", sin STRCAT
 *
 * Aqui ya es facil: tras promover los allocas, `%a` y `%b` son valores SSA, asi
 * que basta mirar si los dos son un @c STRMAKE sobre un literal de tamano
 * constante.  Si lo son, se interna la concatenacion y el @c STRCAT pasa a ser
 * un @c STRMAKE sobre ella: cero trabajo en runtime y una alocacion menos.
 *
 * Encadena solo (el resultado plegado es otro STRMAKE de literal, asi que
 * `a + b + c` se pliega en dos vueltas del punto fijo).
 *
 * Los STRMAKE de las partes NO se tocan: si nadie mas las usa, quedan muertos y
 * los quita el DCE; si se usan en otro sitio, siguen ahi.  Va a nivel de IR,
 * asi que lo heredan el interprete, el JIT y el AOT.
 *
 * @param mod Modulo a transformar in-place (necesita internar la cadena nueva).
 * @return true si plego algun STRCAT.
 */
bool ir_pass_fold_strcat(IrModule &mod);

/**
 * @brief  C2.13: DETECCION (log-only) de objetos GC no-escapantes.
 *
 * Analiza los `call @__new_X(...)` de @p fn y determina cuales NO escapan
 * del frame (su host_ptr solo se usa para leer/escribir campos locales).
 * Si la env var VESTA_ESCAPE_DEBUG esta activa, loguea cada sitio con su
 * veredicto.  NO transforma el IR (siempre devuelve false); existe para
 * validar el analisis de escape con cero riesgo antes de habilitar el
 * scalar replacement.
 *
 * @return siempre false (no modifica el IR).
 */
bool ir_pass_escape_detect_gc(IrFunction &fn);

/**
 * @brief  C2.13: Scalar Replacement de objetos GC no-escapantes.
 *
 * Para cada `new X()` (call @__new_X) que no escapa del frame y cuyo ctor es
 * un inicializador trivial de campos, elimina el alloc GC y reemplaza los
 * field-reads por los valores de construccion (args del new o constantes).
 * Conservador: solo transforma sitios donde TODAS las precondiciones de
 * seguridad se cumplen.  Necesita el @p mod para resolver los ctores.
 *
 * @return true si se transformo algun sitio.
 */
bool ir_pass_scalar_replace_gc(IrFunction &fn, const IrModule &mod);

/**
 * @brief Pase de simplificacion algebraica + folding de cast constantes
 *        + simplificacion de phis triviales.
 *
 * Combina tres familias de transformaciones:
 *
 *   (A) Algebraic identities:  @c add @c x,0 -> x, @c mul @c x,1 -> x,
 *       @c and @c x,-1 -> x, @c xor @c x,x -> 0, etc.  Cubre los
 *       patrones tipicos donde constant-fold deja un identity operator.
 *
 *   (B) Cast de constantes: @c sext.T @c (const @c K) -> @c const.T
 *       @c sign_extend(K).  Idem para @c zext / @c trunc / @c bitcast.
 *       Aplica sobre las cadenas que el frontend Vesta emite cuando
 *       i32 ops se promueven a i64 y vuelven (visible en el JIT como
 *       @c shl rax,32 / @c sar rax,32 sobre un imm-zero).
 *
 *   (C) Phi simplification: @c phi(a,a,a) -> @c mov @c a.  Tambien
 *       @c phi(a,phi_dst,a) -> @c mov @c a (self-ref ignorada).
 *       Cleanup post-DCE para CFGs lineales donde algun phi colapsa.
 *
 * Beneficia IGUAL al JIT (menos instrucciones generadas) y a los
 * port targets (codigo destino mas limpio, e.g. @c port-c).
 *
 * @param fn Funcion a optimizar.
 * @return true si se realizo al menos una transformacion.
 */
bool ir_pass_simplify(IrFunction &fn);

/**
 * @brief Estrecha comparaciones extendidas: @c cmp(sext/zext(x), const) ->
 * @c cmp(x, const_estrecho) cuando el const cabe en el ancho de @c x, y
 * @c cmp(ext(x), ext(y)) -> @c cmp(x, y).  Elimina el SEXT/ZEXT y el const.i64
 * (los mata el DCE).  El backend compara al ancho de los operandos.
 */
bool ir_pass_narrow_cmp(IrFunction &fn);

/**
 * @brief Contrae @c fmul+fadd single-use en un @c FMA (round(a*b+c), 1
 * redondeo).  Solo en funciones @c \@fp(fast) (fn.fp_contract).  Corre DESPUES
 * de @c ir_pass_simplify.  Ver la nota en el .cpp.
 */
bool ir_pass_fuse_fma(IrFunction &fn);

/**
 * @brief Gate global del driver para @c ir_pass_fuse_fma.  velb = true; el AOT
 * lo pone a @c target.caps.fma (no crear FMA si el target no lo soporta).
 */
void ir_set_fma_contract_allowed(bool v);
bool ir_fma_contract_allowed();

/**
 * @brief Pase Strength Reduction.
 *
 * Reemplaza MUL/DIV/MOD por constantes potencia-de-2 con SHL/SHR/AND
 * (mucho mas baratos):
 *   x * 2^k        -> x << k
 *   x / 2^k (uN)   -> x >> k     (unsigned solo, signed con rounding)
 *   x % 2^k (uN)   -> x & (2^k-1)
 *
 * Beneficios:
 *   - JIT skip IMUL/IDIV (caros) -> SHL/SHR (1 ciclo).
 *   - port-C: el optimizador C tambien lo hace, pero IR limpio.
 *
 * @return true si transformo al menos una instr.
 */
bool ir_pass_strength_reduction(IrFunction &fn);

/**
 * @brief Elimina SEXT redundante de variables de induccion no-negativas
 *        acotadas por el test de salida de su loop (ver ir_optimizer.cpp).
 */
bool ir_pass_elim_redundant_casts(IrFunction &fn);

/**
 * @brief Pliega un CMP a CONST 0/1 cuando el RANGE (ValueFacts) prueba el
 *        resultado (siempre true/false).  Habilita poda de ramas muertas.
 */
bool ir_pass_fold_compares(IrFunction &fn);

/**
 * @brief Pliega un CMP a CONST cuando una GUARDA DOMINANTE ya establece una
 *        relacion sobre el mismo par de valores SSA (rango relacional
 *        simbolico / predicate propagation).  Cierra los bounds-checks de
 *        longitud VARIABLE (`if (i >= len) panic` dentro de `for i in 0..len`).
 */
bool ir_pass_fold_guarded_compares(IrFunction &fn);

/**
 * @brief Runner de los consumidores de ValueFacts: computa el analisis UNA vez
 *        y lo comparte entre todos (elim casts + fold compares), recomputando
 *        solo si un consumidor muto el IR.  AnalysisCache minimo.
 */
bool ir_pass_valuefacts_consumers(IrFunction &fn);

/**
 * @brief Pase Reassociation.
 *
 * Reasocia operaciones binarias asociativas para combinar constantes:
 *   (x + c1) + c2  ->  x + (c1+c2)
 *   (x * c1) * c2  ->  x * (c1*c2)
 *   (x & c1) & c2  ->  x & (c1&c2)
 *   Idem para OR, XOR.
 *
 * Habilita const-folding sobre cadenas que const-fold local no veria.
 *
 * @return true si reasocio al menos una expresion.
 */
bool ir_pass_reassoc(IrFunction &fn);

/**
 * @brief Function inlining a nivel modulo.
 *
 * Para cada CALL site cuyo callee este definido en el modulo y cumpla
 * las heuristicas de inlineabilidad, sustituye la CALL con el cuerpo
 * del callee, renombrando SSA values + bloques.
 *
 * v1: solo callees de un solo bloque que terminan en RET.  Cubre
 * wrappers triviales, getters, helpers pequenos.  Multi-block + recursion
 * requieren CFG manipulation mas compleja (deferred a v2).
 *
 * Heuristica:
 *   - Callee no es @c is_native.
 *   - Callee tiene 1 bloque que termina en RET.
 *   - Body < INLINE_THRESHOLD instrucciones.
 *   - Callee != caller (sin self-inline).
 *
 * Beneficios:
 *   - JIT: skip CALL/RET overhead + regalloc ve mas contexto.
 *   - port-C: codigo destino mas legible (menos funciones helper).
 *
 * @param mod Modulo a optimizar (mutado).
 * @param threshold Tamano maximo (en instrs del body) del callee inlineable.
 *        Default 12 (balance code-size en O2).  El C2/OSR sube este valor para
 *        inlinear agresivamente las CALLs de un loop CALIENTE (donde el
 * code-size no importa porque el loop domina el tiempo): elimina el CALL + el
 *        marshalling VM_ABI de args por memoria, que O2 dejo por su heuristica
 *        conservadora.
 * @return true si inline al menos una CALL.
 */
bool ir_pass_inline(IrModule &mod, size_t threshold = 12);

/**
 * @brief Inline de callees MULTI-bloque (con ramas) que el inliner single-block
 *        rechaza.  Cirugia de CFG: split del bloque caller en el CALL, copia de
 *        los bloques del callee (valores + block-ids remapeados), RET -> BR al
 *        merge + PHI del resultado, recompute preds/succs + reorder RPO.
 *        Semantica-preservante.  @p threshold = max instrucciones TOTALES del
 *        callee.  Gated por VESTA_NO_MB_INLINE.
 */
bool ir_pass_inline_multiblock(IrModule &mod, size_t threshold = 24);

/**
 * @brief Inline del CUERPO de una lambda en el CALLCLOSURE (cross-backend).
 *
 * Cuando una funcion construye UNA closure (MAKE_CLOSURE) con capturas
 * by-value y la invoca UNA vez (CALLCLOSURE) en el mismo bloque, este pase
 * sustituye el CALLCLOSURE por el cuerpo del helper @c __lambda_N,
 * mapeando los params -> args y las capturas -> los valores capturados
 * (operands del MAKE_CLOSURE).  Elimina la llamada indirecta + el acceso
 * al env por completo (el DCE posterior limpia las stores/allocs del env
 * que quedan muertas).  Beneficia a TODOS los backends: el interprete y el
 * JIT evitan el dispatch @c vrt_callclosure, y el AOT evita el call
 * indirecto -- mejor que un puntero de funcion de C/C++.
 *
 * Conservador (cero riesgo de mispairing): solo actua si la funcion tiene
 * EXACTAMENTE un MAKE_CLOSURE y un CALLCLOSURE en el mismo bloque, todas
 * las capturas son by-value (no mutable), y el helper es single-block.
 * Ante cualquier anomalia, no transforma (mantiene el CALLCLOSURE).
 *
 * @param mod Modulo a transformar in-place.
 * @return true si inlino al menos una closure.
 */
bool ir_pass_inline_closures(IrModule &mod);

/**
 * @brief Loop-Invariant Code Motion.
 *
 * Detecta loops via back-edges (JMP/BR_COND a un bloque anterior),
 * identifica el pre-header (predecesor del header NO en el loop),
 * y mueve instrucciones cuyos operandos son TODOS invariantes
 * (definidos fuera del loop O constantes) al pre-header.
 *
 * Las invariantes se calculan UNA vez en vez de N veces.  Tipico para
 * patrones como @c for(i;i<size;i++) donde @c size es invariant.
 *
 * v1: solo loops simples con UN back-edge y UN pre-header.  Multi-
 * exit/break/continue/nested loops cubren el caso simple en cada nivel.
 *
 * @return true si movio al menos una instr.
 */
bool ir_pass_licm(
    IrFunction &fn, const analysis::PointsTo *pt = nullptr,
    const std::unordered_set<std::string> *pure_callees = nullptr);

/**
 * @brief Devirtualizacion monomorfica de CALLVIRT a CALL directo.
 *
 * Algoritmo: por cada IR value, rastrea si su origen es un @c call @__new_<X>
 * (clase X conocida).  Para cada CALLVIRT con receptor de clase conocida y
 * @c vtbl_idx, resuelve la IrMethod correspondiente y convierte a CALL
 * directo si es seguro:
 *
 *   - La clase NO esta marcada como @c is_aspect.
 *   - El metodo tiene @c ir_fn_name no vacio (no abstracto/native-only).
 *
 * Skip total del modulo si CUALQUIER clase es @c is_aspect: las CALLVIRTs
 * pueden disparar advice chains en runtime y necesitan dispatch dinamico.
 *
 * Beneficio: elimina vtable lookup + frame OOP (no advice_chain) + reduce
 * inst count.  Habilita el inline pass posterior sobre el CALL directo.
 *
 * @param mod Modulo a optimizar.
 * @return true si convirtio al menos un CALLVIRT.
 */
bool ir_pass_devirt_monomorphic(IrModule &mod);

/**
 * @brief Devirtualizacion de CALLIND a puntero a funcion crudo (cfn) constante.
 *
 * Si el @c func_ptr de un CALLIND viene de un LABEL_ADDR (direccion de una
 * funcion conocida en compile-time), lo reescribe a un CALL directo a esa
 * funcion -- elimina la rama indirecta y habilita el inliner.
 *
 * @param fn Funcion a transformar.
 * @return true si reescribio al menos un CALLIND.
 */
bool ir_pass_devirt_cfn(IrFunction &fn);

/**
 * @brief Devirtualizacion ESPECULATIVA guiada por perfil/IC (C2).
 *
 * A diferencia de @c ir_pass_devirt_monomorphic (estatico, closed-world, sin
 * guard), este pase toma la clase OBSERVADA en runtime en cada call site (de
 * los IC slots del PIC durante el tier-up C1->C2) y emite un dispatch GUARDADO:
 *
 *     cls = load [obj]              ; class_ptr (offset 0, obj es host_ptr)
 *     if (cls == T_const) {         ; T = clase observada (ClassInfo* como
 * CONST) r_fast = call @callee     ; CALL directo -> ir_pass_inline lo inlinea
 *     } else {
 *         r_slow = callvirt obj ... ; dispatch dinamico original (fallback)
 *     }
 *     r = phi [r_fast, r_slow]
 *
 * CORRECTO POR CONSTRUCCION: si la clase observada deja de cumplirse, el guard
 * cae al CALLVIRT original -> mismo resultado.  No necesita deopt (esa es la
 * capa agresiva posterior, C2.7).
 *
 * Cada site identifica su CALLVIRT por @c callvirt_dst (el dst SSA, unico) para
 * poder localizarlo de forma estable aunque se transformen varios sites.
 *
 * @param fn    Funcion (clonada) a transformar.
 * @param sites Lista de sites monomorficos a especular.
 * @return true si transformo al menos un site.
 */
struct SpecDevirtSite {
    IrValueId callvirt_dst;     ///< dst SSA del CALLVIRT objetivo (unico)
    uint64_t class_ptr;         ///< ClassInfo* observado (embebido como CONST)
    std::string callee_ir_name; ///< ir_fn_name del metodo resuelto (a inlinar)
};
bool ir_pass_speculative_devirt(IrFunction &fn,
                                const std::vector<SpecDevirtSite> &sites);

/**
 * @brief Devirtualizacion especulativa ESTATICA via guard-chain (TAREA 2, C2).
 *
 * A diferencia de @c ir_pass_speculative_devirt (runtime, guiado por IC, un
 * solo candidato con @c class_ptr CONST), este pase es COMPILE-TIME y maneja
 * varios candidatos (<=K) tomados del closed-world del modulo: para un dispatch
 * de interfaz/virtual con pocos implementors inlineables, reescribe el call en
 * una CADENA de guardas por tipo + fallback al dispatch original:
 *
 *     cls = load[obj]                          ; class_ptr (offset 0)
 *     if (cls == cls_value_1) r1 = call C1__m(obj, args...)   ; fast 1
 *     elif (cls == cls_value_2) r2 = call C2__m(obj, args...) ; fast 2
 *     ... (hasta K) ...
 *     else                    rN = <CALLITF/CALLVIRT/CALLM original>  ;
 * fallback r = phi(r1, r2, ..., rN)
 *
 * Como el @c ClassInfo* de cada candidato NO es constante en compile-time (se
 * crea en @c __module_init), el @c cls_value de cada candidato es un SSA value
 * que el LOWERING resuelve en el entry (slot-cache lazy via @c findclass) y
 * registra en @c fn.spec_devirt_sites (keyed por el @c dst del call).  Este
 * pase SOLO hace la cirugia CFG con esos datos ya en el IR; el
 * @c ir_pass_inline posterior inlinea los @c CALL directos del fast path.
 *
 * CORRECTO POR CONSTRUCCION: si el tipo del objeto no coincide con ningun
 * candidato (incl. tipos de @c loadmodule), cae al dispatch original ->
 * mismo resultado.  No necesita deopt.
 *
 * v1: solo call sites con @c dst != IR_NO_VALUE (metodos que devuelven valor,
 * no-SRET).  Beneficia tanto al interp como al JIT (ambos bajan este IR).
 *
 * @param fn Funcion a transformar (lee @c fn.spec_devirt_sites).
 * @return true si transformo al menos un site.
 */
bool ir_pass_spec_devirt(IrFunction &fn);

/**
 * @brief Pase de propagacion de copias.
 *
 * Para cada %b = mov.T %a, sustituye todos los usos de %b por %a y
 * elimina el MOV.  Funciona en un unico recorrido.
 *
 * @param fn Funcion a optimizar.
 * @return true si se realizo al menos una sustitucion.
 */
bool ir_pass_copy_prop(IrFunction &fn);

/**
 * @brief Pase de plegado de constantes.
 *
 * Evalua en tiempo de compilacion expresiones cuyos operandos son todas
 * constantes literales (IrValue::is_const).  Soporta ADD/SUB/MUL/DIV/MOD/
 * AND/OR/XOR/NOT/SHL/SHR/SAR/NEG y todas las comparaciones enteras.
 *
 * @param fn Funcion a optimizar.
 * @return true si se plego al menos una instruccion.
 */
bool ir_pass_const_fold(IrFunction &fn);

/**
 * @brief Pase de eliminacion de bloques inalcanzables.
 *
 * Calcula los bloques alcanzables desde el bloque de entrada mediante BFS/DFS
 * y elimina los bloques que no son alcanzables.  Actualiza los predecesores
 * de los bloques restantes y elimina los argumentos phi correspondientes.
 *
 * @param fn Funcion a optimizar.
 * @return true si se elimino al menos un bloque.
 */
bool ir_pass_unreachable(IrFunction &fn);

/**
 * @brief Pase CSE: eliminacion de subexpresiones comunes.
 *
 * Para instrucciones puras con el mismo opcode, tipo y operandos (en orden),
 * sustituye el destino por el de la primera ocurrencia y elimina el duplicado.
 * Solo opera dentro del mismo bloque basico (CSE local).
 *
 * @param fn Funcion a optimizar.
 * @return true si se elimino al menos una instruccion.
 */
bool ir_pass_cse(IrFunction &fn);

/**
 * @brief Pase Dead Store Elimination.
 *
 * Para cada bloque basico, elimina STOREs consecutivos a la misma direccion
 * cuando no hay LOADs ni CALLs intermedios.  Reduce escrituras redundantes
 * en patrones de init list, alloca-zero, etc.
 *
 * @return true si elimino al menos un STORE.
 *
 * @param pure_callees (opcional) conjunto de nombres de funciones cuyo efecto
 *        transitivo es TOTALMENTE PURO (sin lecturas/escrituras de memoria, sin
 *        may_trap/throw/allocate/block/io ni tags, Complete), segun el modelo
 * de efectos.  Una CALL a una de ellas NO es barrera de memoria (el DSE puede
 * eliminar/forwardear a traves).  Es conocimiento INTERPROCEDURAL que el DSE
 * por si solo no tiene; se lo aporta EffectAnalysis.  nullptr = comportamiento
 * clasico (toda CALL es barrera).
 */
/**
 * @brief Hechos que el DSE necesita para tratar el asm con precision.
 *
 * Se le PASAN, no los calcula: son los mismos que ya cachea el gestor de
 * analisis para el resto de los pases, y recalcularlos aqui es rehacer un
 * trabajo cuyo resultado ya existe.  Medido: calcularlos dentro se llevaba el
 * 100 % del pase (30 s de 30 s sobre una funcion de 1740 instrucciones,
 * recalculados una vez por llamada, 1056 veces).
 *
 * Un puntero nulo significa "no los tengo": entonces el pase los calcula, que
 * es lo que hacia siempre.  Asi quien lo llame suelto -- un test, una
 * herramienta -- no tiene que montar un gestor de analisis.
 */
struct HechosDeAsmParaDse {
    const analysis::AsmBindingFacts *ligaduras = nullptr;
    const analysis::IrFacts *estructura = nullptr;
    const analysis::RangeFacts *rangos = nullptr;
};

bool ir_pass_dse(IrFunction &fn, const analysis::PointsTo *pt = nullptr,
                 const std::unordered_set<std::string> *pure_callees = nullptr,
                 const HechosDeAsmParaDse *hechos_asm = nullptr);

/**
 * @brief Pase Const CSE Entry: deduplicacion global de constantes.
 *
 * Para cada CONST en bloques distintos al entry, si ya existe un CONST con
 * mismo (type, imm) en el bloque entry (que domina a todos), reemplazar
 * con MOV.  Util para limpiar duplicados creados por SR/reassoc/LICM.
 * Mas conservador que CSE local (solo CONSTs, no LOADs ni aritmetica).
 *
 * @return true si dedupeo al menos un CONST.
 */
bool ir_pass_const_cse_entry(IrFunction &fn);

/**
 * @brief Pase TCO: optimizacion de llamadas en cola (Tail Call Optimization).
 *
 * Detecta el patron CALL @f(args) seguido de RET %result (o RET void) y
 * convierte el CALL en TAILCALL, eliminando la instruccion RET subsiguiente.
 * Aplica tanto a llamadas recursivas como a llamadas a otras funciones.
 *
 * El pase se activa automaticamente en O2 y superiores.
 *
 * @param fn Funcion a optimizar.
 * @return true si se convirtio al menos una llamada en cola.
 */
bool ir_pass_tailcall(IrFunction &fn);

/**
 * @brief Pase Load Narrow: elide sign-extension redundante tras LOAD
 * i8/i16/i32.
 *
 * Para cada @c LOAD con tipo I8/I16/I32, computa el cierre transitivo de
 * valores derivados via ADD/SUB/MUL/AND/OR/XOR (ops que preservan los bits
 * bajos).  Si todos los usos de cada valor del cierre son: otra op segura de
 * mismo ancho, STORE de mismo ancho, o RET de mismo ancho, marca @c
 * narrow_only=true en el SSA value del LOAD.  El emisor IR salta el patron @c
 * shl/sar de 64-N bits.
 *
 * Ops UNSAFE que abortan la elision: CMP_* (cualquier comparacion 64-bit),
 * SEXT/ZEXT/CAST/BITCAST/TRUNC (anchos cruzados), SHL/SHR/SAR (necesitan bits
 * altos correctos), NEG/NOT (pueden invertir bits altos), SDIV/UDIV/SMOD/UMOD
 * (full register width), PHI (analisis transitivo complejo, mejor abort), CALL
 * (no se inspecciona la callee), STORE/LOAD/RET de ancho distinto.
 *
 * Ahorro tipico: 3 instrucciones VM por LOAD i32 elidido (@c mov scratch,32 +
 * @c shl + @c sar).  En bench_struct_field (3 LOADs i32 por iter, 30M iter) =
 * 270M instrucciones VM ahorradas.
 *
 * @return true si marco al menos un LOAD como narrow_only.
 */
bool ir_pass_load_narrow(IrFunction &fn);

/**
 * @brief Pase List Scheduling: reordena instrucciones dentro de cada
 * basic block para exponer Instruction-Level Parallelism (ILP).
 *
 * Algoritmo clasico: construye un DAG de dependencias (data + memoria +
 * side-effects), computa la longitud del critical path (CPL) por nodo,
 * y emite instrucciones via list scheduling priorizando los de mayor CPL
 * (que tienen mas "tail" -- mas trabajo dependiente despues -- y deben
 * comenzar lo antes posible para no bloquear el critical path).
 *
 * Beneficios:
 *   1. **Interpreter**: el host CPU (out-of-order) ve mas independencia
 *      entre VM ops consecutivos => mas paralelismo via reorder buffer.
 *      Gana ~5-15% en bench ALU pesado.
 *   2. **JIT ( D+)**: el host superscalar puede ejecutar 2-4 host
 *      ops por ciclo si tienen deps disjuntas.  Sin scheduling, una
 *      cadena de adds dependientes (a+=1; a+=1; a+=1) ejecuta 1/ciclo;
 *      con scheduling interleaving (a+=1; b+=1; a+=1; b+=1), 2/ciclo.
 *
 * Restricciones (barreras que NO se reordenan):
 *   - PHIs: deben permanecer al inicio del bloque.
 *   - Terminadores (BR/BR_COND/RET/THROW): al final.
 *   - RAW_ASM, CALL*, NEWOBJ, GC_ALLOC, RAW_ALLOC/FREE, TRYENTER/LEAVE,
 *     SETFIELD, ARRAY_STORE, STORE: barreras conservativas (no reordenan
 *     a traves).  LOAD se ordena despues de STOREs previos.
 *
 * Coste: O(N^2) por basic block para construir el DAG + O(N log N) para
 * la priority queue.  Para bloques tipicos (<100 instrs) negligible.
 *
 * @return true si reordeno al menos un basic block.
 */
bool ir_pass_schedule(
    IrFunction &fn, const analysis::PointsTo *pt = nullptr,
    const std::unordered_set<std::string> *pure_callees = nullptr);

/**
 * @brief Registra un helper @c __new_<X> como "puro" (sin side effects
 *        que requieran preservar la llamada cuando el resultado no se usa).
 *
 * El frontend lo invoca cuando detecta un constructor trivial (sin
 * @c callvirt al ctor user-defined).  El optimizador puede eliminar
 * la llamada al @c __new_<X> si el handle resultante no se usa.
 *
 * Implementacion ligera: un set global de strings consultado por DCE.
 */
void register_pure_new_helper(const std::string &fn_name);

/**
 * @brief Consulta si un helper @c __new_<X> ha sido marcado como puro.
 */
bool is_pure_new_helper(const std::string &fn_name);

} // namespace ir

#endif // IR_OPTIMIZER_H
