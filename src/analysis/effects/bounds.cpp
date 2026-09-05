/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file bounds.cpp
 * @brief Implementacion del comprobador de limites de region (ver bounds.h).
 */
#include "util/env_flags.h"
#include "analysis/effects/bounds.h"

#include "analysis/effects/effect_analysis.h"
#include "analysis/facts/ir_facts.h"
#include "analysis/facts/range_summary.h"
#include "analysis/facts/value_range.h"
#include "analysis/memory/memory_access.h"
#include "ir/ssa_ir.h"

#include <chrono>
#include <cstdlib>
#include <iostream>

namespace analysis {
namespace effects {

namespace {
/// Nombre legible de una region, para la prueba del diagnostico.
std::string nombre_region(AbstractLoc::Kind k, uint32_t id) {
    const char *base = "?";
    switch (k) {
    case AbstractLoc::Kind::Stack: base = "stack"; break;
    case AbstractLoc::Kind::Heap: base = "heap"; break;
    case AbstractLoc::Kind::Global: base = "global"; break;
    default: break;
    }
    return std::string(base) + "#" + std::to_string(id);
}
} // namespace

std::vector<BoundsViolation> check_region_bounds(const ir::IrModule &mod,
                                                 EffectAnalysis *ea_dado) {
    std::vector<BoundsViolation> out;
    /* Interruptor de escape.  La comprobacion esta MEDIDA a cero falsos sobre
     * los 454 programas del corpus, pero un veredicto que rompe una compilacion
     * tiene que poder desactivarse sin tocar el compilador. */
    if (!util::flag_on(util::FlagId::AsaBounds)) return out;

    /* El motor lo trae quien ya lo tenia.  Construir uno propio significa
     * rehacer el escape y los resumenes del modulo entero -- que es justo lo
     * que acaba de hacer el informe para las secciones de arriba. */
    EffectAnalysis propio;
    EffectAnalysis &ea = ea_dado != nullptr ? *ea_dado : propio;

    /* Resumenes de frontera del modulo: lo que entra y sale de cada funcion.
     * Sin ellos, un parametro vale lo que su tipo y el resultado de una llamada
     * es desconocido, con lo que nada que cruce una funcion se puede comprobar.
     * Se calculan UNA vez para todo el modulo.
     *
     * Van ANTES de tocar el motor, y se le dan.  Antes se calculaban despues, y
     * la consecuencia era que el mismo analisis de rangos corria dos veces
     * sobre cada funcion: el motor los calculaba sin resumenes para points-to,
     * y aqui se volvian a calcular con ellos para juzgar.  Dos respuestas
     * distintas a la misma pregunta, y ninguna razon para querer la peor. */
    const analysis::RangeSummaries resumenes =
        analysis::compute_range_summaries(mod);
    ea.usar_resumenes(&resumenes);
    /* Y se los quitamos al salir.  El motor puede venir de fuera y vivir mas
     * que esta funcion, mientras que los resumenes son locales: dejarselos
     * puestos seria dejarle un puntero a algo que ya no existe.  Va como
     * destructor y no al final para que un `return` por el camino -- o una
     * excepcion -- tampoco pueda saltarselo. */
    struct RetirarResumenes {
        analysis::effects::EffectAnalysis &ea;
        ~RetirarResumenes() { ea.usar_resumenes(nullptr); }
    } retirar_resumenes{ea};

    ea.module_summary(mod); // deja el motor con sus tablas listas

    /* Reparto del coste.  Hizo falta: la sospecha era el def-use y no lo era,
     * ni el motor duplicado -- solo midiendo cada parte se llego a la que es.
     */
    const bool medir = util::flag_on(util::FlagId::Times);
    using RelojLim = std::chrono::steady_clock;
    auto marca = RelojLim::now();
    long us_resumenes = 0, us_rangos = 0, us_llamadas = 0;
    long n_llamadas = 0;
    /* Reparto del tiempo DENTRO del recorrido por puntos.  En nanosegundos: en
     * microsegundos, lo que se llama millones de veces se trunca a cero y
     * parece gratis.  Tres candidatos que llevan a arreglos distintos --
     * calcular los rangos, montar el estado de cada bloque, o preguntar por los
     * efectos de cada instruccion -- y solo midiendo se sabe cual paga. */
    long long ns_calcular = 0, ns_montar_estado = 0, ns_efectos = 0;
    long long n_bloques = 0, n_instrs = 0;
    auto cerrar = [&](long &destino) {
        const auto ahora = RelojLim::now();
        destino += static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(ahora - marca)
                .count());
        marca = ahora;
    };

    cerrar(us_resumenes);
    for (const ir::IrFunction &fn : mod.functions) {
        if (fn.blocks.empty()) continue;
        /* Los cuerpos comptime no son parte del programa que se ejecuta: corren
         * al compilar y lo que tocan son datos de la propia compilacion, con
         * desplazamientos que se calculan en ese momento.  Juzgarlos aqui es
         * juzgar otro programa, y lo que sale son avisos sobre codigo que
         * nunca llegara al binario -- un fichero de quince lineas recibia
         * setenta y tres errores por importar `std.memory`, todos de sus
         * generadores. */
        if (ir::es_cuerpo_comptime(fn.name)) continue;
        const analysis::PointsTo &pt = ea.points_to_publico(fn);
        /* Rangos de la funcion: es lo que permite juzgar una region de tamano
         * simbolico.  Se calculan una vez por funcion, no por acceso. */
        // De la cache del motor: reconstruir el def-use aqui era hacerlo por
        // segunda vez, porque el resumen del modulo ya lo pidio.
        const analysis::IrFacts &hechos = ea.facts_publico(fn);
        const auto t_calc = RelojLim::now();
        /* Del MOTOR, no por nuestra cuenta.  Ya lleva los resumenes puestos
         * (se los dimos arriba), asi que son exactamente los mismos rangos que
         * usa points-to -- una sola ejecucion del analisis por funcion, no dos
         * respondiendo lo mismo con distinta informacion.  Y viene por
         * referencia desde su cache: ni se recalcula ni se copia. */
        const analysis::RangeFacts &rangos = ea.ranges_publico(fn);
        ns_calcular += std::chrono::duration_cast<std::chrono::nanoseconds>(
                           RelojLim::now() - t_calc)
                           .count();
        cerrar(us_rangos);
        /* Si alguna cota de bucle esta INFERIDA, aqui no se acusa.
         *
         * Rechazar un programa es afirmar que el acceso se sale SIEMPRE, y eso
         * exige una prueba.  Una cota sacada del extremo de un rango es una
         * sobre-aproximacion: puede cubrir vueltas que el bucle no da, y
         * entonces el acceso "que se sale" es de una vuelta que no ocurre.
         *
         * Paso de verdad con la cola de un bucle vectorizado
         * (`187_vectorize_unary`): siete `f64`, indice de 0 a 6, y la cola
         * dejaba en el intermedio un acceso guardado en el indice 7 que no se
         * ejecuta.  Con la variable sin acotar nadie decia nada; al acotarla,
         * el desplazamiento se fijaba en 56 sobre un objeto de 56 bytes y se
         * rechazaba un programa correcto.
         *
         * Se pierde deteccion en esas funciones, y es lo correcto: un falso
         * positivo que no deja compilar es peor que un aviso que falta, sobre
         * todo cuando el que falta no era demostrable. */
        if (rangos.bounds_inferred) continue;
        /* Se prestan al modelo de efectos: ya estan calculados aqui arriba, y
         * si no se los damos cada bloque de asm los recalcula recorriendo la
         * funcion entera.  Se retiran al acabar con esta funcion para que no
         * puedan usarse con la siguiente. */
        ea.prestar_rangos(&fn, &rangos);
        struct RetirarRangos {
            analysis::effects::EffectAnalysis &ea;
            ~RetirarRangos() { ea.prestar_rangos(nullptr, nullptr); }
        } retirar{ea};
        /* UN recorrido para toda la funcion, recolocado en cada bloque.
         *
         * Montaba uno por bloque, y montarlo incluye derivar el suelo de cada
         * valor de la funcion -- lo que impone su tipo, y su valor si es
         * constante --, que no depende del bloque.  O sea que una funcion con B
         * bloques y V valores hacia B*V veces un trabajo que es V. */
        analysis::RangeWalk paso(fn, hechos, rangos, 0);
        for (uint32_t bi = 0; bi < fn.blocks.size(); ++bi) {
            const ir::IrBlock &b = fn.blocks[bi];
            /* Se recorre el bloque con el estado del analisis, no se consulta
             * por valor: el rango de un indice EN EL PUNTO DEL ACCESO es el que
             * llevan las guardas -- `if (i < n) buf[i]` --, y el de su
             * definicion no sabe nada de ellas. */
            const auto t_montar = RelojLim::now();
            paso.situar(bi);
            ns_montar_estado +=
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    RelojLim::now() - t_montar)
                    .count();
            ++n_bloques;
            for (const ir::IrInstr &in : b.instrs) {
                // El estado del punto se consume SIEMPRE, salga la revision por
                // donde salga: saltarselo desalinearia el recorrido.
                struct Avance {
                    analysis::RangeWalk &w;
                    ~Avance() { w.avanzar(); }
                } avance{paso};
                /* En un punto al que no se llega no hay nada que comprobar, y
                 * senalarlo seria acusar a codigo que no se ejecuta. */
                if (!paso.reachable()) continue;
                ++n_instrs;
                const auto t_ef = RelojLim::now();
                const EffectAnalysisResult r = ea.local(fn, in);
                ns_efectos +=
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        RelojLim::now() - t_ef)
                        .count();
                auto revisa = [&](const LocSet &ls, bool escribe) {
                    if (ls.is_top) return;
                    for (const AbstractLoc &l : ls.locs) {
                        if (l.width <= 0 || !l.concrete()) continue;
                        /* La extension se indexa por VALUE-ID, y solo Stack y
                         * Heap tienen ahi su raiz: en `ArgDerived` el
                         * identificador es el INDICE DEL PARAMETRO, asi que
                         * consultarlo devolveria la extension de un valor sin
                         * relacion.  De un parametro no se sabe el tamano -- lo
                         * sabe quien llama --, asi que no se afirma nada. */
                        if (l.kind != AbstractLoc::Kind::Stack &&
                            l.kind != AbstractLoc::Kind::Heap)
                            continue;
                        const analysis::RegionExtent &ex = pt.extent_of(l.id);
                        int64_t tope = 0;
                        int64_t objeto = 0;
                        if (ex.constante()) {
                            tope = ex.limite();
                            objeto = ex.bytes;
                        } else if (ex.simbolica()) {
                            /* Tamano SIMBOLICO: se sabe QUE valor lo manda, y
                             * con su rango se puede acotar.  Para AFIRMAR que
                             * un acceso se sale hace falta pasarse del tamano
                             * MAXIMO posible -- si el mayor `malloc` que ese
                             * valor puede pedir no llega, ninguno llega.  Con
                             * el minimo no se prueba nada: solo diria que
                             * PODRIA salirse, y eso no es un error. */
                            const ValueRange &rr = rangos.at(ex.sym);
                            int64_t rlo, rhi;
                            if (!rr.acotada() ||
                                !rr.vista_con_signo(rlo, rhi) || rhi < 0)
                                continue;
                            tope = rhi;
                            objeto = rhi;
                        } else {
                            continue;
                        }
                        const int64_t fin = l.off + l.width;
                        if (l.off >= 0 && fin <= tope) continue;
                        BoundsViolation v;
                        v.function = fn.name;
                        v.line = in.source_line;
                        v.write = escribe;
                        v.width = l.width;
                        v.off = l.off;
                        v.limite = tope;
                        v.objeto = objeto;
                        v.region = nombre_region(l.kind, l.id);
                        out.push_back(std::move(v));
                    }
                };
                revisa(r.effects.mem.writes, true);
                revisa(r.effects.mem.reads, false);

                /* Y lo que hace una LLAMADA sobre la memoria de AQUI.
                 *
                 * El efecto de una funcion habla de sus parametros -- `memset`
                 * escribe "desde su primer parametro, tantos bytes" --, y eso
                 * dentro de ella no se puede juzgar: el tamano de la region lo
                 * sabe quien llama.  Es justo lo que dice la nota de mas abajo
                 * sobre los parametros, y la conclusion que faltaba sacar: hay
                 * que mirarlo AQUI, sustituyendo cada parametro por el
                 * argumento de esta llamada.
                 *
                 * Sin esto, una funcion que rellena mas bytes de los que caben
                 * compilaba sin una palabra, y el fallo aparecia pisando la
                 * variable de al lado. */
                if (in.op == ir::IrOp::CALL || in.op == ir::IrOp::TAILCALL ||
                    in.op == ir::IrOp::CALLN) {
                    /* Que la lista no sea COMPLETA no impide juzgar lo que si
                     * hay en ella: cada una de esas escrituras ocurre, y si una
                     * se sale es un fallo aunque haya mas que no se pudieron
                     * nombrar.  Para acusar no hace falta saberlo todo, hace
                     * falta que lo que se sabe sea cierto. */
                    const auto t_ll = RelojLim::now();
                    const EfectoEnLlamada ll = ea.at_call_site(fn, in);
                    us_llamadas +=
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            RelojLim::now() - t_ll)
                            .count();
                    ++n_llamadas;
                    revisa(ll.escribe, true);
                    revisa(ll.lee, false);
                }

                /* Acceso INDEXADO (`buf[i]`).  El modelo colapsa el offset no
                 * constante a "todo el objeto", asi que el bucle de arriba se
                 * calla.  Pero no saber CUANTO vale el desplazamiento no es no
                 * saber nada: se sabe QUIEN lo decide, y con su rango se puede
                 * juzgar.
                 *
                 * Y para AFIRMAR que se sale tiene que salirse el intervalo
                 * ENTERO.  Un rango es una SOBRE-aproximacion: que su extremo
                 * inferior caiga fuera no prueba nada, porque el resto del
                 * intervalo puede caer dentro -- y el suelo que da el tipo
                 * (`[INT32_MIN, INT32_MAX]` para un `i32`) cumple eso siempre.
                 * Comprobar solo el minimo daba 17 falsos en la suite con
                 * desplazamientos de -2147483648: no era un indice, era el
                 * ancho del tipo. */
                const bool es_acceso =
                    (in.op == ir::IrOp::LOAD || in.op == ir::IrOp::STORE);
                if (!es_acceso || in.operands.empty()) continue;
                const ir::IrValueId vptr =
                    (in.op == ir::IrOp::LOAD)
                        ? in.operands[0]
                        : (in.operands.size() > 1 ? in.operands[1]
                                                  : ir::IR_NO_VALUE);
                if (vptr == ir::IR_NO_VALUE) continue;
                const PointsToEntry &pe = pt.at(vptr);
                if (util::flag_on(util::FlagId::BoundsDebug))
                    std::fprintf(stderr,
                                 "[bounds] fn=%s linea=%u kind=%d exact=%d "
                                 "rango=%d [%lld,%lld]\n",
                                 fn.name.c_str(), in.source_line, (int)pe.kind,
                                 pe.off_exact ? 1 : 0, pe.off_rango ? 1 : 0,
                                 (long long)pe.off_lo, (long long)pe.off_hi);

                if (pe.off_exact || !pe.off_rango) continue;
                if (pe.kind != AbstractLoc::Kind::Stack &&
                    pe.kind != AbstractLoc::Kind::Heap)
                    continue;
                const analysis::RegionExtent &ex2 = pt.extent_of(pe.root);
                if (!ex2.constante()) continue;
                /* El intervalo viene de la entrada, compuesto al derivar la
                 * direccion.  Pero ahi el indice se acoto en SU DEFINICION, y
                 * aqui se sabe mas: entre medias pudo pasar por una guarda.  Se
                 * rehace la suma con el rango DE ESTE PUNTO, que solo puede ser
                 * igual o mas estrecho. */
                int64_t off_lo = pe.off_lo, off_hi = pe.off_hi;
                if (pe.off_sym != ir::IR_NO_VALUE) {
                    const ValueRange rp = paso.rango(pe.off_sym);
                    int64_t rlo = 0, rhi = 0;
                    int64_t l = 0, h = 0;
                    if (rp.acotada() && rp.vista_con_signo(rlo, rhi) &&
                        !__builtin_add_overflow(pe.off_base, rlo, &l) &&
                        !__builtin_add_overflow(pe.off_base, rhi, &h) &&
                        l <= h) {
                        off_lo = l;
                        off_hi = h;
                    }
                }
                if (off_lo > off_hi) continue;
                const int32_t w = analysis::memory_access_size(in.type);
                if (w <= 0) continue;
                /* El final del acceso mas alto.  Con freno: el intervalo puede
                 * llegar al mayor entero -- es lo que vale un desplazamiento
                 * del que solo se sabe su tipo -- y sumarle el ancho ahi daria
                 * la vuelta, convirtiendo "no se nada" en "todo cae antes del
                 * objeto".  Un calculo que se desborda no prueba nada. */
                int64_t fin_alto;
                if (__builtin_add_overflow(off_hi, static_cast<int64_t>(w),
                                           &fin_alto))
                    continue;
                // Entero fuera: o todo el intervalo cae PASADO el final del
                // objeto, o todo el cae ANTES del principio.  Cualquier otra
                // cosa es una parte dentro y otra fuera: sospecha, no error.
                const bool todo_pasado = (off_lo >= ex2.limite());
                const bool todo_antes = (fin_alto <= 0);
                if (!todo_pasado && !todo_antes) continue;
                BoundsViolation v;
                v.function = fn.name;
                v.line = in.source_line;
                v.write = (in.op == ir::IrOp::STORE);
                v.width = w;
                v.off = off_lo;
                v.limite = ex2.limite();
                v.objeto = ex2.bytes;
                v.region = nombre_region(pe.kind, pe.root);
                out.push_back(std::move(v));
            }
        }
    }
    cerrar(us_rangos);
    if (medir)
        std::cerr << "[limites] " << mod.functions.size() << " funciones, "
                  << n_llamadas << " llamadas | resumenes " << us_resumenes
                  << " us (" << resumenes.rondas << " pasos) | rangos+recorrer "
                  << us_rangos << " us | en-la-llamada " << us_llamadas
                  << " us\n"
                  << "[limites]   reparto: calcular " << (ns_calcular / 1000000)
                  << " ms | montar estado " << (ns_montar_estado / 1000000)
                  << " ms (" << n_bloques << " bloques) | efectos "
                  << (ns_efectos / 1000000) << " ms (" << n_instrs
                  << " instrs) | recorrer "
                  << ((long long)us_rangos / 1000 - ns_calcular / 1000000 -
                      ns_montar_estado / 1000000 - ns_efectos / 1000000)
                  << " ms\n";
    return out;
}

} // namespace effects
} // namespace analysis
