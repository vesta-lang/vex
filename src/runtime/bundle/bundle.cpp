/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/bundle.cpp
 * @brief Formacion y ejecucion de paquetes de instrucciones.
 *
 * Ver `include/runtime/bundle.h` para el porque y el diseno.
 */

#include <cstddef>
#include "util/vesta_memcpy.h"

#include "runtime/bundle.h"

#if VM_BUNDLES

#include "bytecode/bytecode.h"
#include "runtime/decode_instruction.h"
#include "disasm/disasm.h" // asm real en los volcados de la cache
#include "runtime/instr_db_vm.h" // nombre del opcode en los volcados
#include "util/env_flags.h" // VESTA_CACHE_DUMP: volcado del estado de caches
#include "runtime/bundle/fuse_report.h"
#include "runtime/bundle/bundle_touch_all.h"
#include "runtime/bundle/predecode.h"
#include "runtime/bundle/liveness.h"
#include "runtime/bundle/ooo.h"
#include "runtime/exec_instruction.h"

/* ALINEAR EL BUCLE A LA VENTANA DE CAPTACION: probado y NO compensa.
 *
 * Al alinear `Bundle::instr` a linea de cache, el perfil de hardware decia que
 * lo que empeoraba era el FRONT-END, no la memoria: `Front-End Bound` del 5,0%
 * al 22,3%, `Retiring` del 67,1% al 48,8% y `Split Loads` a CERO en los dos --
 * o sea que no habia ni una carga partida y el problema era donde caia el
 * CODIGO, no el dato --.  La ventana de captacion de esta microarquitectura es
 * de 32 bytes y GCC alinea bucles a 16, asi que subirlo parecia lo indicado.
 *
 * Con `#pragma GCC optimize("align-loops=32")` sobre esta unidad, medido
 * intercalado y en tres muestras por punto:
 *
 *     independ:256:paquetes   458 -> 499   (recupera la mitad)
 *     mixta:1024:paquetes     305 -> 316   (recupera todo)
 *     alu:260:paquetes        348 -> 335   (lo pierde)
 *
 * Y sobre los 1008 puntos del barrido, 302,8 contra 303,8: ruido.  Reparte el
 * tiempo de sitio sin ganar nada, y a cambio ata la unidad a un pragma no
 * portable con efectos secundarios conocidos en GCC.  No entra. */

namespace runtime {

namespace {

/* La telemetria se pide en EJECUCION, no al construir.
 *
 * Antes vivia detras de `VM_BUNDLE_STATS`, y eso significaba que para MIRAR por
 * que un programa forma los paquetes que forma habia que reconstruir el
 * proyecto entero -- y entonces lo que se mira ya no es el binario que se
 * ejecuta --.  Una medida que obliga a cambiar de binario para tomarla mide
 * otro binario.
 *
 * Y no cuesta lo que parece: NINGUNO de estos contadores va por instruccion.
 * Van por paquete formado, por despacho o por encadenamiento, o sea una vez
 * cada treinta y tantas instrucciones ejecutadas.  Una rama que casi siempre no
 * se toma ahi no se mide.
 *
 * OJO: apagada, el argumento de `BSTAT_ADD` SE SIGUE EVALUANDO, y tiene que ser
 * asi.  Ahi dentro va la llamada que hace el trabajo, no solo la que produce el
 * numero; que la cuenta desaparezca no puede hacer desaparecer el reorden. */
#define BSTAT(p, field)                                                        \
    do {                                                                       \
        if (__builtin_expect((p)->bundle_stats_on, 0))                         \
            ++(p)->bundle_stats.field;                                         \
    } while (0)
#define BSTAT_ADD(p, field, n)                                                 \
    do {                                                                       \
        const uint64_t vm_bstat_n = (uint64_t)(n);                             \
        if (__builtin_expect((p)->bundle_stats_on, 0))                         \
            (p)->bundle_stats.field += vm_bstat_n;                             \
    } while (0)
/// Como `BSTAT` pero sobre una casilla de un array de motivos.  El indice se
/// evalua siempre, igual que el argumento de `BSTAT_ADD` y por lo mismo.
#define BSTAT_IDX(p, field, i)                                                 \
    do {                                                                       \
        const size_t vm_bstat_i = (size_t)(i);                                 \
        if (__builtin_expect((p)->bundle_stats_on, 0))                         \
            ++(p)->bundle_stats.field[vm_bstat_i];                             \
    } while (0)

/**
 * @brief Si esta instruccion NO puede ir dentro de un paquete.
 *
 * El criterio es REENTRAR: una instruccion que sale del interprete y puede
 * volver a entrar invalida lo que `exec_bundle` sostiene mientras ejecuta --
 * `head`, que apunta DENTRO de la icache de mapeo directo, y el `Bundle*` de la
 * arena.  La reentrada descodifica, y descodificar desaloja entradas.
 *
 * La lista NO se fue encontrando a base de reventones: sale de mirar que
 * manejadores alcanzan un sumidero que vuelve a ejecutar bytecode o sale al
 * host.  Los sumideros son tres:
 *   - `finalize_all_live` / `execute_instruction` / `decode_instruction`
 *     -- vuelven a entrar al interprete (finalizadores del GC).
 *   - `invoke_native*` -- salen a codigo del host, que puede llamar de vuelta.
 *   - `enter_jit` -- salta a codigo compilado.
 *
 * Buscandolos de una en una llevaba dos (`hlt` y `calln`, las que reventaron);
 * derivandolas del codigo salen SIETE.  Las otras cinco no habian dado la cara
 * todavia.
 *
 * Se comparan PUNTEROS A FUNCION y no indices de opcode: un indice mal puesto
 * es un fallo silencioso, y renombrar un manejador aqui es un error de
 * compilacion.
 *
 * Aun asi esto sigue siendo una lista aparte que puede quedarse vieja: el dia
 * que alguien anada un opcode que toque el GC, el fallo vuelve.  Si esto llega
 * a entrar de verdad, la propiedad tiene que vivir en @c InstrFormat, declarada
 * por quien anade el opcode.
 */
bool is_reentrant(const DecodedInstr &d) {
    const auto f = d.exec_cached;

    // Siempre: salen a codigo del host o ejecutan finalizadores.
    if (f == &exec_instr_calln || f == &exec_instr_callni ||
        f == &exec_instr_callvmr || f == &exec_instr_hlt)
        return true;

    /* Las llamadas de VM a VM (`callvm`, `callvirt`, `tailcall`) SI entran.
     *
     * Su unico sumidero es `enter_jit`, y lo que las hacia inseguras no era
     * reentrar en si: era que la reentrada podia desalojar la entrada de icache
     * que `exec_bundle` sostiene.  Con la entrada ANCLADA (`icache_pinned`) eso
     * ya no puede pasar, asi que la exclusion sobra.
     *
     * Y meterlas dentro es justo lo que se buscaba: el encadenado las sigue
     * hasta el paquete del destino, que es INLINAR la llamada; y con `callvirt`
     * sigue el destino REALMENTE resuelto, que es devirtualizar por
     * observacion. Las dos cosas alargan el tramo recto, que es lo que limita
     * el ILP.
     *
     * Se probo antes gatearlas por `g_pc_jit_active` y se descarto: ata la
     * correccion del interprete al estado del JIT -- que es independiente -- y
     * ademas tiene carrera, porque la bandera cambia mientras el programa
     * corre. */
    return false;
}

BundleArena *arena_of(ProcessVM *p) {
    if (p->bundle_arena == nullptr) {
        p->bundle_arena = new BundleArena();
        /* Quien pide la telemetria DESDE FUERA la pide una vez, aqui: la
         * variable de entorno se lee una sola vez por proceso y no en cada
         * incremento.  Un test que la quiera la enciende por su cuenta y no
         * necesita variable ninguna. */
        if (::util::flag_on(::util::FlagId::BundleStats))
            p->bundle_stats_on = true;
        if (::util::flag_on(::util::FlagId::BundleOoo)) p->bundle_ooo_on = true;
    }
    return static_cast<BundleArena *>(p->bundle_arena);
}

/* Descriptor sintetico de las entradas de paquete.
 *
 * Hay DOS puertas de despacho y hay que tapar las dos:
 *   - el hot path del scheduler llama a `d->exec_cached(...)`,
 *   - `execute_instruction` -- el camino lento, y el que usan los tests y el
 *     depurador -- llama a `decoded_ptr->metadata->exec(...)`.
 *
 * Redirigiendo solo `exec_cached`, por la segunda puerta se ejecutaba la
 * cabecera como instruccion normal... pero con los operandos ya pisados por el
 * indice de arena.  Reventaba.
 *
 * Con `metadata` apuntando aqui, NADIE lee ya los operandos de la entrada: la
 * copia buena de la cabecera vive en el paquete. */
runtime::InstrFormat g_bundle_format = {
    "bundle",
    Assembly::Bytecode::AddressingMode::COUNT,
    Assembly::Bytecode::InstrSizeMode::FIXED_1,
    &exec_bundle,
    nullptr,
};

} // namespace

/**
 * @brief Vuelca el ESTADO de las caches: que hay dentro ahora mismo.
 *
 * No cuenta nada durante la ejecucion -- RECORRE las estructuras cuando se le
 * pide --, asi que el camino caliente no paga ni una instruccion por que esto
 * exista.  Por eso puede vivir detras de una variable de entorno y usarse sobre
 * el binario que se entrega, en vez de exigir una compilacion aparte como la
 * telemetria de contadores.
 *
 * Son dos preguntas distintas y conviene no confundirlas: los contadores dicen
 * QUE HA PASADO (cuantas veces se formo, se abandono, se recogio) y esto dice
 * COMO ESTA (cuanto se esta usando, cuanto queda, que sigue vivo).
 */
[[gnu::cold]] static void bundle_dump_state(const ProcessVM *process) {
    // Ocupacion de la icache y cuantas de sus entradas son cabeceras.
    uint32_t filled = 0, heads = 0;
    for (uint32_t i = 0; i < ICACHE_SIZE; ++i) {
        const DecodedInstr &e = process->icache[i];
        if (e.exec_cached == nullptr) continue;
        ++filled;
        if (e.exec_cached == &exec_bundle) ++heads;
    }

    std::fprintf(stderr,
                 "\n[caches pid=%llu] icache: %u/%u ocupadas (%.1f%%), %u son "
                 "cabeceras de paquete\n",
                 (unsigned long long)process->pid.local_pid, filled,
                 (unsigned)ICACHE_SIZE,
                 100.0 * (double)filled / (double)ICACHE_SIZE, heads);

    const auto *arena = static_cast<const BundleArena *>(process->bundle_arena);
    if (arena == nullptr) {
        std::fprintf(stderr, "                 paquetes: sin arena\n");
        return;
    }
    /* Las dos regiones.  `viva` es donde se reserva ahora; la otra esta
     * vacia salvo que quede una recoleccion por rematar. */
    for (uint32_t h = 0; h < 2; ++h) {
        const auto &half = arena->half[h];
        std::fprintf(stderr,
                     "                 region %u%s: %u/%u paquetes, %u bloques "
                     "pedidos (%zu KB)\n",
                     h, h == arena->current ? " (viva)" : "", half.used,
                     (unsigned)BundleArena::CAPACITY, half.n_chunks,
                     (size_t)half.n_chunks * BundleArena::Half::CHUNK_BYTES /
                         1024);
    }
    /* Cabeceras y paquetes reservados no tienen por que cuadrar: un paquete
     * cuya cabecera desalojo la icache sigue ocupando sitio hasta la proxima
     * recoleccion.  La diferencia ES la basura pendiente. */
    std::fprintf(stderr,
                 "                 vivos %u de %u reservados -> %u por "
                 "reciclar\n",
                 heads, arena->half[arena->current].used,
                 arena->half[arena->current].used > heads
                     ? arena->half[arena->current].used - heads
                     : 0u);

    /* CONFLICTOS: cuantas cabeceras caen en el mismo conjunto.  Es la cifra que
     * distingue "la cache se ha llenado" de "el indice las esta amontonando", y
     * las dos se arreglan de forma OPUESTA -- una pide mas sitio, la otra pide
     * dispersar --.  Sin esto se confunden: aqui la cache estaba al 9,4% y aun
     * asi desalojaba. */
    uint32_t by_size[16] = {};
    {
        // Se cuenta sobre las heads VIVAS, recorriendo sus pc.
        for (uint32_t i = 0; i < ICACHE_SIZE; ++i) {
            const DecodedInstr &e = process->icache[i];
            if (e.exec_cached != &exec_bundle) continue;
            const Bundle *b = bundle_of(e);
            if (b == nullptr || b->k == 0) continue;
            const uint32_t n = b->k < 16 ? b->k : 15;
            ++by_size[n];
        }
    }
    std::fprintf(stderr, "                 tamano de paquete:");
    for (uint32_t n = 1; n < 16; ++n)
        if (by_size[n] != 0)
            std::fprintf(stderr, " %u:%u", n, by_size[n]);
    std::fprintf(stderr, "%s\n", by_size[15] ? " (15 = 15 o mas)" : "");
}

void bundle_dump(const ProcessVM *process) { bundle_dump_state(process); }


void bundle_dump_one(ProcessVM *process, const Bundle *b) {
    /* El CONTENIDO, que es lo que hace falta el dia que algo va mal: que
     * instrucciones lleva el paquete y en que direccion esta cada una.  Con el
     * histograma se ve la forma; con esto se ve el caso.
     *
     * El `pc` de cada instruccion se guarda al formar, no se deduce del orden.
     * Eso importa aqui mas que en ningun sitio: en cuanto se reordene, deducirlo
     * daria la direccion equivocada, y un volcado de depuracion que miente es
     * peor que no tenerlo. */
    if (b == nullptr) {
        std::fprintf(stderr, "  (paquete nulo)\n");
        return;
    }
    std::fprintf(stderr,
                 "  paquete k=%u entradas=%u ejecutadas=%u retirado=%s\n", b->k,
                 b->entries, b->executed, b->retired ? "si" : "no");
    bundle_dump_asm(process, b);
}

/**
 * @brief Escribe @p s y lo rellena hasta @p width columnas VISIBLES.
 *
 * El desensamblador colorea su salida, asi que las cadenas llevan secuencias
 * ANSI dentro: `%-33s` cuenta esos bytes invisibles como ancho y la columna
 * sale corrida justo en las lineas que mas cuesta leer.  Aqui se cuenta lo que
 * de verdad ocupa en pantalla -- todo lo que va entre `ESC[` y la `m` final no
 * ocupa nada -- y se rellena con eso.
 *
 * @param s     Cadena, posiblemente con secuencias ANSI.
 * @param width Columnas visibles que debe ocupar como minimo.
 */
[[gnu::cold]] static void fput_padded(const char *s, int width) {
    int visible = 0;
    for (const char *p = s; *p != '\0'; ++p) {
        if (*p == '\x1B') {                     // arranca una secuencia ANSI
            while (*p != '\0' && *p != 'm') ++p; // hasta su terminador
            if (*p == '\0') break;
            continue; // no ocupa columnas
        }
        ++visible;
    }
    std::fputs(s, stderr);
    for (int i = visible; i < width; ++i) std::fputc(' ', stderr);
}

void bundle_dump_asm(ProcessVM *process, const Bundle *b) {
    /* El ENSAMBLADOR de lo que hay en la cache, con su direccion virtual.
     *
     * El nombre del opcode no basta para depurar: dice `adds` pero no sobre que
     * registros ni con que inmediato, que es justo lo que se necesita saber
     * cuando un paquete hace algo raro.  Aqui se leen los BYTES REALES de la
     * memoria de la VM en la direccion de cada instruccion y se pasan por el
     * mismo desensamblador que `--disasm-file`, con lo que se ve exactamente lo
     * que se veria mirando el programa -- y se puede contrastar con el.
     *
     * Leer de `vm_mem` y no del `DecodedInstr` es deliberado: si alguna vez el
     * paquete guardara algo distinto de lo que hay en memoria, esto lo
     * ensenaria en vez de taparlo. */
    if (b == nullptr || process == nullptr) return;

    // Lo que ocupa como mucho una instruccion; el desensamblador nunca lee mas.
    constexpr uint32_t kMaxBytes = 16;
    uint8_t buf[kMaxBytes];
    for (uint32_t i = 0; i < b->k && i < BUNDLE_MAX; ++i) {
        const DecodedInstr &d = b->instr[i];
        const uint32_t n =
            d.flags_info.size_instr != 0 ? d.flags_info.size_instr : kMaxBytes;
        process->vm_mem.read_bytes(d.pc, buf, n);

        disasm::DisasmOptions opts;
        opts.show_hex = true;
        const auto out = disasm::disasm_bytes(buf, n, d.pc, opts);
        if (out.empty()) {
            std::fprintf(stderr, "    [%2u] 0x%08llx  <no se pudo leer>\n", i,
                         (unsigned long long)d.pc);
            continue;
        }
        const disasm::DisasmResult &r = out.front();
        /* El hex va a 33 columnas porque una instruccion de VM llega a 11
         * bytes ("00 " por byte = 33): con menos, las que son largas empujan
         * el mnemonico y la columna deja de estar alineada justo en las filas
         * que mas cuesta leer.  Y se rellena contando columnas VISIBLES: estas
         * cadenas vienen coloreadas. */
        std::fprintf(stderr, "    [%2u] 0x%08llx  ", i,
                     (unsigned long long)r.address);
        fput_padded(r.hex.c_str(), 33);
        std::fputs("  ", stderr);
        fput_padded(r.mnemonic.c_str(), 8);
        std::fputc(' ', stderr);
        std::fputs(r.operands.c_str(), stderr);
        std::fputc('\n', stderr);
    }
}

void bundle_dump_heads(ProcessVM *process, uint32_t max_lines,
                       bool with_instructions) {
    /* Volcado DETALLADO, para depurar un caso concreto: cada cabecera viva con
     * lo que el paquete ha hecho.  No sale solo -- se pide desde el depurador o
     * desde un test -- porque con miles de cabeceras seria ilegible.
     *
     * `entradas` y `ejecutadas` son las que decide la retirada: por debajo de
     * `MIN_PER_ENTRY` instrucciones por entrada el paquete no compensa y se
     * devuelve la ranura.  Verlas es la unica forma de entender por que un
     * paquete concreto se retiro. */
    std::fprintf(stderr, "\n[cabeceras pid=%llu]  pc  k  entradas  ejecutadas  "
                         "por_entrada  retirado\n",
                 (unsigned long long)process->pid.local_pid);
    uint32_t shown = 0;
    for (uint32_t i = 0; i < ICACHE_SIZE && shown < max_lines; ++i) {
        const DecodedInstr &e = process->icache[i];
        if (e.exec_cached != &exec_bundle) continue;
        const Bundle *b = bundle_of(e);
        if (b == nullptr) continue;
        std::fprintf(stderr, "  0x%08llx  %2u  %8u  %10u  %11.1f  %s\n",
                     (unsigned long long)e.pc, b->k, b->entries, b->executed,
                     b->entries ? (double)b->executed / (double)b->entries : 0.0,
                     b->retired ? "si" : "no");
        // La linea de arriba ya dice lo que el paquete ha hecho; aqui va lo que
        // LLEVA, entero.  Por eso se llama al desensamblado y no a
        // `bundle_dump_one`, que repetiria esa misma linea.
        if (with_instructions) bundle_dump_asm(process, b);
        ++shown;
    }
}

void bundle_release(ProcessVM *process) {
    // Cualificado desde la raiz: dentro de `runtime` hay otro `util` que
    // sombrearia al del proyecto.
    if (__builtin_expect(::util::flag_on(::util::FlagId::CacheDump), 0))
        bundle_dump_state(process);
    /* La telemetria de paquetes existia y NO LA IMPRIMIA NADIE: los contadores
     * se llenaban y morian con el proceso.  Una medida que no se puede leer no
     * es una medida, asi que se vuelca aqui, que es donde el proceso termina.
     *
     * NADA de esto va ya bajo `#if VM_BUNDLE_STATS`: los contadores se piden en
     * EJECUCION -- `bundle_stats_on` o `VESTA_BUNDLE_STATS` -- y por tanto se
     * pueden ver sin reconstruir.  Atarlo al perfil de construccion obligaba a
     * cambiar de binario para tomar la medida, y entonces se mide otro binario.
     *
     * Hubo un paso intermedio peor que ninguno de los dos extremos: los del
     * reordenamiento en ejecucion y el resto al compilar, con una nota
     * diciendo cuales faltaban.  Media telemetria es la que hace perder el
     * tiempo, porque el que la lee no sabe si un cero es "no paso" o "no se
     * midio".
     *
     * PERO RECOGER Y VOLCAR SON DOS COSAS, y confundirlas se nota enseguida:
     * esto corre una vez POR PROCESO, asi que un banco que crea decenas
     * escupia el bloque decenas de veces en medio de su propia tabla.  Se
     * vuelca solo si lo pidieron DESDE FUERA -- la variable de entorno --;
     * quien enciende `bundle_stats_on` por codigo es porque va a leer los
     * contadores el mismo y no quiere que nadie los imprima por su cuenta. */
    const auto &s = process->bundle_stats;
    if (::util::flag_on(::util::FlagId::BundleStats) &&
        (s.dispatches != 0 || s.formed != 0)) {
        std::fprintf(
            stderr,
            "\n[paquetes] formados=%llu no_formados=%llu aplazados=%llu "
            "recolecciones=%llu\n"
            "           despachos=%llu instr_dentro=%llu  -> %.1f por despacho\n"
            "           abandonos=%llu encogidos=%llu encadenados=%llu "
            "cabeceras_movidas=%llu\n"
            "           fusionados=%llu pares\n"
            /* Cuanto movio el planificador, en INSTRUCCIONES y no en paquetes:
             * lo que interesa es si de verdad reordena algo, no cuantas veces
             * se le llamo.  Sobre el total de las que entraron en un paquete da
             * la proporcion real. */
            "           reordenadas=%llu (%.1f%% de las que entran) en %llu "
            "paquetes\n"
            /* POR QUE se movieron.  Con el total solo se sabe cuanto; esto dice
             * que criterio lo decidio, que es lo que permite ajustar los pesos
             * mirando datos en vez de a ojo. */
            "           decidio: fusion=%llu independencia=%llu localidad=%llu "
            "orden=%llu  de %llu elecciones\n",
            (unsigned long long)s.formed, (unsigned long long)s.not_formed,
            (unsigned long long)s.flushes, (unsigned long long)s.collects,
            (unsigned long long)s.dispatches,
            (unsigned long long)s.instrs_in_bundles,
            s.dispatches ? (double)s.instrs_in_bundles / (double)s.dispatches
                         : 0.0,
            (unsigned long long)s.aborts, (unsigned long long)s.shrinks,
            (unsigned long long)s.chained, (unsigned long long)s.head_shifts,
            (unsigned long long)s.fused, (unsigned long long)s.reordered,
            s.instrs_in_bundles
                ? 100.0 * (double)s.reordered / (double)s.instrs_in_bundles
                : 0.0,
            (unsigned long long)s.reorder_bundles,
            (unsigned long long)s.reorder_wins[0],
            (unsigned long long)s.reorder_wins[1],
            (unsigned long long)s.reorder_wins[2],
            (unsigned long long)s.reorder_wins[3],
            (unsigned long long)s.reorder_choices);

        /* Lo de la FUSION lo imprime su informe, que vive aparte: aqui se
         * decide cuando se vuelca, no como se formatea. */
        fuse_dump(process);

        /* El REPARTO entre nucleos.  Los dos numeros juntos: cuantos paquetes
         * se podian partir y en cuantos el ayudante lo cogio de verdad.  Con
         * uno solo no se distingue "no hay donde partir" de "hay donde pero el
         * traspaso nunca llega a tiempo". */
        if (s.ooo_searched == 0) {
            /* NADIE MIRO.  Decir "partibles=0" aqui seria decir "no hay donde
             * partir", que es otra cosa: la busqueda va con el reparto porque
             * cuesta un 8%, y sin el no llega a correr. */
            std::fprintf(stderr,
                         "           reparto: NO SE BUSCO (pide "
                         "VESTA_BUNDLE_OOO; buscar cuesta ~8%%)\n");
        } else {
            std::fprintf(stderr,
                         "           reparto: partibles=%llu  repartidos=%llu"
                         "  (de %llu mirados)\n",
                         (unsigned long long)s.ooo_splittable,
                         (unsigned long long)s.ooo_split,
                         (unsigned long long)s.ooo_searched);
            /* Y el TAMANyO del bocado, que es lo que decide si compensa.  Va
             * en la misma linea que los recuentos porque se leen juntos: cien
             * mil repartos de seis instrucciones cada uno no son reparto, son
             * cien mil traspasos. */
            if (s.ooo_split != 0)
                std::fprintf(stderr,
                             "                    %.1f instr por entrega "
                             "(%llu delegadas)\n",
                             (double)s.ooo_delegated / (double)s.ooo_split,
                             (unsigned long long)s.ooo_delegated);
            /* Y CUANTAS VECES hubo que parar.  Es la cifra que dice si esto
             * llego a ser una tuberia: una parada por entrega es el fork-join
             * de antes con otro nombre, y entonces el reparto no puede ganar
             * por mucho que crezca la racion. */
            if (s.ooo_split != 0)
                std::fprintf(stderr,
                             "                    %llu paradas -- %.2f por "
                             "entrega (1.00 = no hay tuberia)\n",
                             (unsigned long long)s.ooo_drains,
                             (double)s.ooo_drains / (double)s.ooo_split);
        }
        /* El ANALISIS delegado, que es la otra mitad del reparto y se lee
         * aparte.  Las tres cifras contestan tres preguntas distintas:
         * cuantos se encargaron, cuantos se quedaron CRUDOS por falta de sitio
         * -- correctos pero sin optimizar --, y cuantos llego a ESTRENAR el
         * hilo de ejecucion.  Preparar mucho y estrenar poco significa que la
         * version buena llega tarde, que no es lo mismo que no prepararla. */
        if (s.ooo_prepares != 0 || s.ooo_prepares_lost != 0)
            std::fprintf(stderr,
                         "           analisis: encargados=%llu  aqui=%llu  "
                         "estrenados=%llu\n",
                         (unsigned long long)s.ooo_prepares,
                         (unsigned long long)s.ooo_prepares_lost,
                         (unsigned long long)s.ooo_improved);
        /* La descodificacion adelantada, que es el encargo mas caro que se le
         * quita al camino critico.  El porcentaje es la cifra: llegar tarde se
         * lee igual que no haberlo intentado, y no es lo mismo. */
        if (s.predecode_hits != 0 || s.predecode_misses != 0) {
            const uint64_t tot = s.predecode_hits + s.predecode_misses;
            std::fprintf(stderr,
                         "           adelantado: %llu de %llu fallos de icache "
                         "ya venian descodificados (%.1f%%)\n",
                         (unsigned long long)s.predecode_hits,
                         (unsigned long long)tot,
                         100.0 * (double)s.predecode_hits / (double)tot);
        }
        /* Y POR QUE no se delego, cuando no se delego.  Con "repartidos=0" a
         * secas no se sabe si es que no hay paralelismo o si una condicion mia
         * lo descarta todo, y eso ya ha costado dos suposiciones seguidas.
         *
         * Los dos ultimos motivos importan mas de lo que parece: "la cola
         * estaba llena" significa que el ayudante NO da abasto, que es el
         * problema contrario a no encontrar trabajo independiente, y confundir
         * los dos lleva a arreglar lo que no es. */
        static const char *const kWhyNot[6] = {
            "lleva algo que transfiere control",
            "lleva algo que lee rip",
            "depende de lo que ya esta en vuelo",
            "la cola estaba llena",
            "el ayudante lo tiene otro proceso",
            "todavia no lo ha analizado nadie"};
        for (uint32_t i = 0; i < 6; ++i)
            if (s.ooo_reject[i] != 0)
                std::fprintf(stderr, "             %-42s %10llu\n", kWhyNot[i],
                             (unsigned long long)s.ooo_reject[i]);
    }
    /* Antes de soltar la arena: que no quede ningun encargo apuntando a ella ni
     * a este proceso, y devolver el ayudante para que lo use el siguiente.
     *
     * Las dos cosas en este orden y las dos obligatorias.  Sin la espera, un
     * encargo vivo escribiria en memoria ya liberada; sin soltar al duenyo, el
     * primer proceso se lo queda para siempre y todos los demas se quedan sin
     * reparto Y SIN ANALISIS, o sea con paquetes crudos.  Eso ultimo no falla
     * -- solo rinde menos --, que es como estuvo pasando sin que nadie lo
     * viera. */
    if (process->bundle_ooo_on) {
        ooo_drain_all();
        /* Y VACIAR lo adelantado, que es de ESTE programa.
         *
         * La tabla se indexa por `pc` y guarda el `pc` como etiqueta, asi que
         * dos programas distintos tienen entradas indistinguibles para la misma
         * direccion.  Mirar solo al duenyo no basta: el duenyo se compara por
         * PUNTERO y los punteros se reciclan -- un proceso nuevo en la misma
         * direccion que el anterior pasa la comprobacion y hereda sus
         * instrucciones --.
         *
         * Se vacia ANTES de soltar al duenyo: entre las dos cosas no puede
         * haber un instante en el que otro proceso ya sea duenyo y la tabla
         * todavia tenga lo viejo. */
        predecode_clear();
        /* Y que el ayudante SUELTE la pagina que tenga cacheada, por la misma
         * razon por la que se vacia lo adelantado: la memoria de este proceso
         * esta a punto de liberarse y su cache guarda un puntero a ella.  Sin
         * esto, el proceso siguiente pedia la misma direccion virtual, la cache
         * acertaba, y se adelantaba lo que hubiera quedado en esa memoria
         * reciclada -- publicado bajo un `pc` legitimo --. */
        ooo_new_epoch();
        ooo_release_owner(process);
    }
    delete static_cast<BundleArena *>(process->bundle_arena);
    process->bundle_arena = nullptr;
}

/**
 * @brief Copia lo vivo a la otra region, publica el cambio y reserva la vieja.
 *
 * Las RAICES son las entradas de icache: se recorren todas, y cada una que sea
 * cabecera de paquete se copia a la region nueva y se repunta ahi.  Lo que
 * ninguna referencia -- retirado, o huerfano porque la icache lo desalojo --
 * no se copia y desaparece: la copia ES la recoleccion.
 *
 * No se reinicia la region vieja aqui.  Puede haber un `Bundle*` suyo en manos
 * de `exec_bundle`, incluso ANIDADO: una instruccion de dentro de un paquete
 * puede provocar un fallo de icache que llegue hasta aqui.  Mientras la vieja
 * no se toque, ese puntero sigue siendo valido; reiniciarla es lo que hay que
 * aplazar, y de eso se encarga @ref bundle_grace_point.
 *
 * @param process Proceso cuya cache se recoge.
 */
[[gnu::cold]] static void bundle_collect(ProcessVM *process) {
    BundleArena *arena = arena_of(process);
    BundleArena::Half &to = arena->spare();

    to.reset(); // la nueva empieza vacia; sus bloques ya estan pedidos

    /* NO hace falta comprobar en que region vive cada paquete, y eso quita un
     * recorrido de bloques por raiz.  El invariante lo garantiza: tras cada
     * recoleccion TODAS las raices vivas quedan repuntadas a la region nueva, y
     * las formaciones posteriores reservan de esa misma.  Luego cualquier
     * cabecera apunta siempre a la region ACTUAL, que es justo la que se esta
     * vaciando aqui. */
    for (uint32_t i = 0; i < ICACHE_SIZE; ++i) {
        DecodedInstr &root = process->icache[i];
        if (root.exec_cached != &exec_bundle) continue;
        Bundle *old = bundle_of(root);
        if (old == nullptr) continue;

        Bundle *fresh = to.alloc();
        // Imposible por la cota: no hay mas vivos que raices, y una region
        // tiene sitio para `CAPACITY` >= `ICACHE_SIZE`.
        if (fresh == nullptr) break;
        *fresh = *old;
        /* Publicacion: una escritura de 64 bits alineada.  Quien lea ve la
         * vieja o la nueva, y las dos valen mientras la vieja siga en pie. */
        bundle_store(&root, fresh);
    }

    arena->current ^= 1u; // la nueva pasa a ser la actual
    /* La vieja se reinicia en el punto de gracia.  La bandera vive en el
     * PROCESO y no en la arena: se mira al salir de cada paquete, o sea en
     * camino caliente. */
    process->bundle_needs_grace = true;
    BSTAT(process, collects);
}

namespace {

/**
 * @brief Prepara un paquete recien formado: reordena, fusiona y busca corte.
 *
 * Va APARTE de `bundle_try_form`, y sin inlinar a proposito.  Metido dentro,
 * el cuerpo de `bundle_touch_all` -- una pasada por instruccion con dos
 * consultas a tablas cada una -- se expandia en linea y engordaba la funcion
 * que se llama en CADA fallo de icache.  Se veia justo donde tenia que verse:
 * en los bloques cortos, que son los que forman mas a menudo, y solo en los
 * motores de paquetes; los escalares no se movieron ni un punto.
 *
 * @param process Proceso duenyo del paquete.
 * @param b       Paquete recien formado, todavia local.
 * @param next_pc Direccion de la instruccion siguiente al paquete.
 */
/**
 * @brief Copia de @p src a @p dst la cabecera y SOLO las `k` instrucciones.
 *
 * La asignacion de struct mueve `sizeof(Bundle)` -- 2.176 bytes -- siempre,
 * incluidas las ranuras que el paquete no usa.  Un paquete de 13 necesita
 * 128 + 13*64 = 960, o sea menos de la mitad, y los tramos cortos son los que
 * mas veces se forman.
 *
 * Se copia por partes en vez de con la asignacion entera para que el tamano lo
 * ponga `k` y no `BUNDLE_MAX`.  Los campos previos al array son una cabecera
 * contigua, asi que van de una pieza.
 */
static void bundle_copy_head_and_k(Bundle &dst, const Bundle &src) {
    /* Con la copia del proyecto, no la de la biblioteca estandar: esa elige el
     * mejor camino de ESTA CPU en ejecucion, que es como se aprovecha un ancho
     * mayor sin subir `-march` -- el binario tiene que seguir arrancando en
     * cualquier maquina --.
     *
     * La cabecera son 128 bytes de tamano CONSTANTE, asi que el despachador se
     * pliega hasta dejar la copia recta.
     *
     * Y el array va con la version CON TIPO, que cuenta objetos en vez de
     * bytes: asi el despachador sabe `alignof(DecodedInstr)` al compilar y se
     * ahorra el prologo que alinea el destino en ejecucion -- que es lo que
     * convierte un tamano en variable y le impide desenrollar el bucle --. */
    ::util::vesta_memcpy(&dst, &src, offsetof(Bundle, instr));
    ::util::vesta_memcopy(dst.instr, src.instr, src.k);
}

[[gnu::noinline]] void bundle_prepare(ProcessVM *process, Bundle &b,
                                      uint64_t next_pc,
                                      vm::VirtualMemory::PageView *view) {
    /* QUE TOCA cada instruccion, UNA sola vez.
     *
     * Los tres pasos que vienen detras -- reordenar, fusionar y buscar por
     * donde partir -- necesitan exactamente esto, y cada uno lo calculaba por
     * su cuenta: ~32 consultas a la tabla de efectos, otras tantas a la de
     * formas y un `regs_of_form` por instruccion, TRES veces.  Medido: anadir
     * el tercero costo un 19% en el motor de paquetes, que ni reordena ni
     * fusiona.
     *
     * Quien MUEVE instrucciones mueve esto con ellas -- el reordenador permuta,
     * el fusionador compacta --.  Ver `bundle_touch_all`.
     *
     * Y se calcula solo si alguno de los tres va a mirarlo.  El motor de
     * paquetes a secas no reordena ni fusiona ni reparte: calcularselo igual
     * seria anadirle una pasada por instruccion que nadie lee, y eso se ve --
     * costaba un 8%. */
    const bool want_reorder =
        process->bundle_reorder_on &&
        !::util::flag_on(::util::FlagId::NoBundleReorder);
    const bool want_split = process->bundle_ooo_on;
    BundleTouch tc;
    if (__builtin_expect(want_reorder || process->bundle_fuse_on || want_split,
                         1))
        bundle_touch_all(b, tc);

    /* REORDENAR antes de publicar.  Aqui y no al ejecutar: se paga una vez por
     * sitio y se cobra en cada una de las miles de entradas siguientes.
     *
     * Se hace sobre `b`, que todavia es local: si algo saliera mal, el paquete
     * que se publica es el que ya estaba bien formado. */
    if (__builtin_expect(want_reorder, 1))
        /* Sin `BSTAT_ADD`: la telemetria del reordenamiento la lleva el propio
         * `bundle_reorder`, que sabe ademas QUE criterio decidio cada posicion.
         * Sumarla tambien aqui contaba dos veces lo mismo. */
        (void)bundle_reorder(process, b, tc);

    /* FUSIONAR, despues de reordenar y antes de publicar.
     *
     * Este orden no es casual: reordenar es lo que deja pegado un productor con
     * su consumidor, y solo un par PEGADO se puede convertir en una sola
     * instruccion.  Y va sobre `b`, que sigue siendo local: `k` cambia, y
     * publicar un paquete a medio fusionar seria publicar otro programa. */
    /* Lo que sigue vivo detras del paquete.  Se saca aqui y no dentro del
     * fusionador porque hace falta el proceso para leer el bytecode, y de paso
     * queda contado cuando la mirada se queda CIEGA -- que es una respuesta
     * distinta de "el temporal sigue vivo", aunque las dos impidan fusionar. */
    if (__builtin_expect(process->bundle_fuse_on, 1)) {
        const FuseTelemetry tel = {process->bundle_stats.fuse_reject,
                                   process->bundle_stats.uncovered,
                                   process->bundle_stats.unmatched_second,
                                   &process->bundle_stats.newop_ready,
                                   &process->bundle_stats.newop_livewall};
        BSTAT_ADD(process, fused,
                  bundle_fuse(b, tc, process, next_pc, view,
                              process->bundle_stats_on ? &tel : nullptr));
    }

    /* Y QUE TOCA el paquete entero, para poder decidir al ejecutarlo si se le
     * puede dar al ayudante sin volver a mirarlo instruccion a instruccion.
     *
     * Se resume AQUI, al formar, que es donde se puede pensar; ejecutar solo
     * lee seis bytes.  Y solo con el reparto pedido: es una pasada mas por
     * formacion, y engancharla a las ESTADISTICAS hacia que mirar los numeros
     * los cambiara -- el banco de MIPS las enciende para su informe --.
     *
     * Cuando no corre, la telemetria dice "no se busco" en vez de "0
     * delegados", que se leeria como "no hay nada que repartir" siendo otra
     * cosa muy distinta. */
    if (want_split) {
        BSTAT(process, ooo_searched);
        /* El resumen del paquete ENTERO, del mismo `tc` que ya esta calculado.
         *
         * Ya no se busca un corte DENTRO del paquete: eso repartia media
         * docena de instrucciones y esperaba en el sitio.  Ahora la unidad es
         * el paquete entero y la pregunta es otra -- puede irse tal cual? --,
         * que se contesta con una union de mascaras. */
        // Ya se ha mirado: se quita la marca de "no se sabe".
        Bundle::Summary su;
        su.flags = 0;
        for (uint32_t i = 0; i < b.k; ++i) {
            su.reg_read = (uint16_t)(su.reg_read | tc.t[i].reg_read);
            su.reg_write = (uint16_t)(su.reg_write | tc.t[i].reg_write);
            su.vec_read = (uint16_t)(su.vec_read | tc.t[i].vec_read);
            su.vec_write = (uint16_t)(su.vec_write | tc.t[i].vec_write);
            su.field = (uint8_t)(su.field | tc.t[i].field_read |
                                 tc.t[i].field_write);
            if (tc.t[i].mem) su.flags |= Bundle::SUM_MEM;
            if (tc.kind[i] == TouchKind::Barrier) su.flags |= Bundle::SUM_BARRIER;
            if (tc.kind[i] == TouchKind::ReadsPc) su.flags |= Bundle::SUM_READS_PC;
        }
        b.summary = su;
        if ((su.flags & Bundle::SUM_NOT_DELEGABLE) == 0)
            BSTAT(process, ooo_splittable);
    }
}

} // namespace

void bundle_prepare_worker(ProcessVM *process, Bundle &b, uint64_t next_pc,
                           vm::VirtualMemory::PageView &view) {
    bundle_prepare(process, b, next_pc, &view);
}

/**
 * @brief Reinicia la region vieja.  Camino FRIO del punto de gracia.
 *
 * Que la cache sea de UN proceso simplifica esto muchisimo: no hacen falta
 * epocas por planificador ni esperar a nadie mas.  Basta con que este proceso
 * no este dentro de ningun paquete, y eso es un contador.
 */
[[gnu::cold]] void bundle_grace_slow(ProcessVM *process) {
    BundleArena *arena = static_cast<BundleArena *>(process->bundle_arena);
    process->bundle_needs_grace = false;
    if (arena == nullptr) return;
    arena->spare().reset(); // contador a cero; los bloques se quedan
}

void bundle_try_form(ProcessVM *process, DecodedInstr *slot, uint64_t pc) {
    if (!process->bundles_on) return;

#if ICACHE_HEAD_SHIFT
    /* DESPLAZAR LA CABECERA cuando su ranura ya la ocupa OTRA cabecera viva.
     *
     * Las cabeceras de paquete estan REGULARMENTE espaciadas -- `k`
     * instrucciones por su tamano --, y un indice que enmascara una direccion
     * en bytes convierte un paso regular en un puñado de ranuras: con k=32 y
     * instrucciones de 4 bytes, una cabecera cada 128 y solo 32 ranuras
     * alcanzables de 4096.  Cuanto MEJOR empaqueta, mas separadas quedan y
     * peor es.
     *
     * Aqui se ataca desde la formacion en vez del indice: si la ranura ya
     * tiene una cabecera de otra direccion, no se forma en `pc`.  Esa
     * instruccion se queda normal, y al ejecutarla el fallo siguiente cae en
     * `pc + tamano`, que es otra ranura.  El desplazamiento sale solo.
     *
     * Es REACTIVO, no aleatorio: solo actua donde hay colision de verdad, y no
     * toca `k`, que sigue significando lo que significaba -- la longitud del
     * tramo recto --.  El precio es un despacho de mas por entrada a esa
     * region.
     *
     * No oscila: si se declina en `pc`, la condicion sigue siendo la misma la
     * proxima vez, asi que `pc` no llega a ser cabecera nunca y la cabecera se
     * queda fija en `pc + tamano`. */
    if (process->icache_head_clash == pc) {
        process->icache_head_clash = UINT64_MAX;
        BSTAT(process, head_shifts);
        return;
    }
#endif

    /* ARENA LLENA: se comprueba LO PRIMERO, y esto no es un detalle de estilo.
     *
     * Estaba al FINAL, despues del bucle que descodifica hasta `BUNDLE_MAX`
     * instrucciones por adelantado -- o sea despues de hacer todo el trabajo
     * que este corte existe para evitar.  Con la arena llena se descodificaban
     * 32 instrucciones y se tiraban, en cada fallo de icache, para siempre.
     *
     * Medido con `VM_BUNDLE_STATS=1` sobre un tramo recto de 8192
     * instrucciones: 5.015.813 rechazos por arena llena, o sea ~160 millones
     * de descodificaciones desperdiciadas a ~13 ns cada una.  El caso rendia
     * 3 MIPS donde el mismo programa con tramos de 4096 rinde 350.
     *
     * El coste ahora es una comparacion.  Sigue sin formarse nada -- eso lo
     * arregla el reciclado de la arena, que es otra cosa -- pero deja de
     * costar. */
    BundleArena *arena = arena_of(process);
    if (arena->total() >= BundleArena::CAPACITY) {
        /* Llena: se RECOGE.  Copiar lo vivo a la otra region y seguir.
         *
         * Antes esto era `return` y no se volvia a formar nunca: la cache
         * funcionaba un rato y luego se apagaba.  Y la comprobacion estaba al
         * FINAL, despues de descodificar 32 instrucciones por adelantado, asi
         * que con la region llena se hacia todo ese trabajo para tirarlo --
         * 5.015.813 veces en un tramo recto de 8192, medido.
         *
         * No se recoge si hay un paquete EJECUTANDOSE: la copia repunta las
         * raices y el que corre dejaria de ser alcanzable a mitad.  En ese caso
         * se salta esta formacion y se recoge en la siguiente, que llegara
         * enseguida. */
        if (process->bundle_depth != 0) {
            BSTAT(process, flushes);
            return;
        }
        bundle_collect(process);
    }

    // Una cabecera de paquete no puede ser a su vez parte de otro: la entrada
    // que se acaba de escribir tiene que ser una instruccion normal.
    if (slot->exec_cached == nullptr || slot->exec_cached == &exec_bundle) {
        BSTAT(process, not_formed);
        return;
    }

    // Tampoco puede ENCABEZAR un paquete una instruccion reentrante: si
    // encabeza, `exec_bundle` la ejecuta igual y la reentrada invalida los
    // punteros lo mismo.  Excluirla solo del cuerpo dejaba el fallo vivo.
    if (is_reentrant(*slot)) {
        BSTAT(process, not_formed);
        return;
    }

    // Se van leyendo las siguientes SIN efectos secundarios: `decode_peek` solo
    // lee, no toca `decoded_ptr`, ni la icache, ni el estado del proceso.
    //
    // Se sigue el flujo SECUENCIAL, sin intentar adivinar a donde salta nada.
    // Si en el camino hay un salto, el paquete lo incluye igual y es el
    // manejador quien, al ver `did_jump` en ejecucion, abandona el resto.  Se
    // decide con el destino REAL en vez de con uno predicho al formar.
    /* SE CONSTRUYE EN LA ARENA, no en una local que luego se copia.
     *
     * Un `Bundle` mide 2.176 bytes.  Construirlo en la pila y volcarlo despues
     * era una copia entera por formacion en el camino sin reparto, y DOS con
     * el -- una para la version que se publica y otra para la que el ayudante
     * reordena --.  Construyendo aqui, el camino sin reparto no copia nada y
     * el del reparto se queda en una sola copia, que esa si es irreducible: el
     * ayudante necesita su propia version mientras el principal ejecuta la
     * cruda.
     *
     * Hay que reservar ANTES de saber si el tramo dara para un paquete, asi
     * que si no da se devuelve la ranura -- ver `BundleArena::undo_alloc` --.
     * Y no puede colarse otra reserva por medio: descodificar por delante no
     * toca la arena, que es lo que dice el comentario de arriba. */
    Bundle *rec = arena->alloc();
    if (rec == nullptr) {
        BSTAT(process, not_formed);
        return;
    }
    Bundle &b = *rec;
    b.k = 1;
    b.improved = nullptr; // la ranura se reutiliza: no heredar la anterior
    b.instr[0] = *slot;
    // El pc va DENTRO de la instruccion, no en un array paralelo: se pone una
    // vez aqui y el bucle de ejecucion no lo toca.  `DecodedInstr` ya tiene el
    // campo, asi que el array aparte solo anadia otra linea de cache que
    // recorrer por paquete.
    b.instr[0].pc = pc;

    uint64_t next_pc = pc + slot->flags_info.size_instr;
    while (b.k < BUNDLE_MAX) {
        DecodedInstr ins;
        if (!decode_peek(process, next_pc, ins)) break; // fin de codigo
        if (ins.exec_cached == nullptr && ins.metadata != nullptr)
            ins.exec_cached = ins.metadata->exec;
        if (ins.exec_cached == nullptr) break; // opcode sin implementacion

        // Una instruccion reentrante corta el paquete aqui: ver `is_reentrant`.
        if (is_reentrant(ins)) break;
        b.instr[b.k] = ins;
        b.instr[b.k].pc = next_pc;
        ++b.k;
        next_pc += ins.flags_info.size_instr;
    }

    if (b.k < 2) {
        // Una sola instruccion no es un paquete: seria pagar la indireccion de
        // la arena para no ahorrar ni un despacho.  La ranura se devuelve.
        arena->undo_alloc();
        BSTAT(process, not_formed);
        return;
    }

    /* La comprobacion de arena llena ya se hizo ARRIBA, antes de descodificar
     * nada.  Aqui solo queda reservar.
     *
     * Sigue pendiente el RECICLADO: al llenarse se deja de formar y no se
     * vuelve a formar nunca, porque vaciar aqui invalidaria las entradas de
     * icache que apuntan a paquetes muertos.  El diseno acordado para eso son
     * dos arenas que se turnan con copia dirigida por la icache. */
    /* La instruccion de ESTA direccion, guardada ANTES de reordenar.
     *
     * Es la que se devuelve a la entrada de icache si el paquete no compensa y
     * se retira.  Tiene que copiarse aqui y no leerse de `instr[0]` mas tarde,
     * porque el planificador puede poner otra en el hueco cero.  Ver
     * `Bundle::head`. */
    b.head = b.instr[0];

    /* PREPARAR: aqui mismo, o en el ayudante.
     *
     * Reordenar y fusionar no depende de ningun registro ni de ninguna memoria
     * del programa -- es una funcion de las instrucciones, y esas ya estan --,
     * asi que se puede hacer en otro nucleo mientras este ejecuta.  Y conviene:
     * corre en CADA fallo de icache, o sea en el camino critico, y en los
     * bloques cortos eso llego a medirse en un 8%.
     *
     * Con el reparto encendido, el paquete se publica CRUDO y la version buena
     * llega despues.  Publicar crudo es correcto: las dos cosas son
     * optimizaciones, no semantica, asi que lo unico que pasa mientras tanto es
     * que las primeras vueltas van sin reordenar ni fusionar. */
    bool delegated = false;
    if (__builtin_expect(process->bundle_ooo_on, 0)) {
        /* La copia la reserva ESTE hilo, porque la arena no es de varios.  Y
         * solo si la cola tiene hueco: reservarla para descubrir despues que no
         * cabe seria gastar una ranura de arena por nada. */
        Bundle *scratch =
            ooo_pending() < kOooSlots ? arena->alloc() : nullptr;
        if (scratch != nullptr) {
            /* Y se copian solo las `k` que HAY, no las 32 que caben.
             *
             * La asignacion de struct movia los 2.176 bytes siempre, incluidas
             * las ranuras vacias.  Un paquete de 13 instrucciones necesita
             * 128 + 13*64 = 960 bytes, o sea menos de la mitad; y los tramos
             * cortos son justo los que mas veces se forman. */
            bundle_copy_head_and_k(*scratch, b);
            delegated = ooo_push_prepare(process, rec, scratch, next_pc);
            if (delegated) BSTAT(process, ooo_prepares);
            if (!delegated) arena->undo_alloc(); // el scratch no se usa
        }
        /* Y de paso, que vaya DESCODIFICANDO lo que viene detras.
         *
         * Este es el sitio donde se sabe: acabamos de recorrer el tramo hasta
         * `next_pc`, asi que lo siguiente que el programa va a descodificar
         * empieza justo ahi.  Se piden dos paquetes por delante para que le de
         * tiempo a llegar antes que el principal.
         *
         * Si no cabe en la cola se pierde y no pasa nada: el principal
         * descodifica como siempre.  Por eso no se apunta como fallo. */

        if (process->ooo_try_decode)
            (void)ooo_push_decode(process, next_pc, BUNDLE_MAX * 2);
    }
    /* Si no se pudo delegar, se prepara AQUI.
     *
     * Antes se dejaba crudo, y eso era un agujero: a un paquete ya formado no
     * vuelve a preguntarle nadie, asi que "no cabia en la cola" se convertia en
     * "sin reordenar ni fusionar PARA SIEMPRE".  Medido en un tramo recto
     * largo: 32 de 65 paquetes se quedaban asi, o sea la mitad del programa
     * corriendo sin optimizar.  Prepararlo aqui cuesta exactamente lo que
     * costaba antes de que existiera el reparto. */
    if (!delegated) {
        // Sobre `b`, que YA ES la ranura de la arena: no queda copia ninguna.
        bundle_prepare(process, b, next_pc, nullptr);
        if (process->bundle_ooo_on) BSTAT(process, ooo_prepares_lost);
    }

    // La entrada pasa a ser cabecera de paquete: `pc` se queda (es la clave del
    // acierto) y `exec_cached` cambia de destino.  El hot path no se entera.
    // Las DOS puertas: el hot path va por `exec_cached`, el camino lento por
    // `metadata->exec`.  Con las dos redirigidas, los operandos de la entrada
    // ya no los lee nadie y el hueco de `raw1` queda libre para el indice.
    slot->exec_cached = &exec_bundle;
    slot->metadata = &g_bundle_format;
    // La TERCERA puerta: el computed-goto del run_loop no mira `exec_cached`
    // ni `metadata`, saca el destino de `flags_info`.  Hay que mandarlo a
    // `L_SLOW`, que es el unico camino que llama a `exec_cached`.
    slot->flags_info.is_not_extended = BUNDLE_DISPATCH_SLOT;
    slot->flags_info.did_jump = false;
    slot->flags_info.blocking = false;
    bundle_store(slot, rec);
    BSTAT(process, formed);
}

void exec_bundle(ProcessVM *process, const DecodedInstr &d) {
    Bundle *b = bundle_of(d);
    /* RECOGER la version preparada, si el ayudante ya la dejo.
     *
     * Una carga y una rama por DESPACHO -- no por instruccion --, y en x86-64
     * un `acquire` de puntero alineado es una carga normal.  El intercambio lo
     * hace ESTE hilo, que es el unico que escribe la entrada de icache: el
     * ayudante solo publica el puntero.  Asi no hay dos hilos escribiendo lo
     * mismo en ningun momento.
     *
     * El paquete crudo no se libera: la arena no recicla todavia, y en cuanto
     * la entrada apunta a la version buena nadie vuelve a mirarlo. */
    if (__builtin_expect(b->improved != nullptr, 0)) {
        Bundle *imp = __atomic_load_n(&b->improved, __ATOMIC_ACQUIRE);
        b->improved = nullptr; // ya recogido: no volver a mirarlo
        bundle_store(const_cast<DecodedInstr *>(&d), imp);
        b = imp;
        BSTAT(process, ooo_improved);
    }
    // `head` es la entrada de icache por la que ENTRO el run_loop, y no cambia
    // aunque se encadenen paquetes: es en ella donde hay que dejar `did_jump` y
    // `blocking`, porque es la que el run_loop va a mirar al volver.
    DecodedInstr *const head = process->decoded_ptr;
    /* Anclada mientras dure el paquete: dentro, `decoded_ptr` apunta a la
     * arena y no protegeria esta entrada.
     *
     * Con guarda y no a mano porque de aqui se sale por cinco sitios --
     * bloqueo, salto, fin del paquete, y los dos del encadenado --, y un ancla
     * que se quede puesta convierte una ranura de icache en inservible para el
     * resto del programa. */
    struct Pin {
        ProcessVM *p;
        explicit Pin(ProcessVM *proc, DecodedInstr *e) : p(proc) {
            p->icache_pinned = e;
            /* Profundidad de anidamiento en paquetes.  Cuenta, no es un
             * booleano, porque SE ANIDA: una instruccion de dentro de un
             * paquete puede provocar un fallo de icache que forme otro.
             *
             * Es lo que hace segura la recoleccion.  Mientras sea distinta de
             * cero hay un `Bundle*` en manos de alguien, asi que ni se copia ni
             * se reinicia nada; al volver a cero se pasa por el punto de
             * gracia. */
            ++p->bundle_depth;
        }
        ~Pin() {
            p->icache_pinned = nullptr;
            /* Camino caliente: un decremento, una comparacion y una rama que
             * casi siempre no se toma.  El trabajo de verdad esta detras, en
             * una funcion marcada FRIA para que no engorde este bucle. */
            if (__builtin_expect(--p->bundle_depth == 0 && p->bundle_needs_grace,
                                 0))
                bundle_grace_slow(p);
        }
    } pin(process, head);

    BSTAT(process, dispatches);

#if BUNDLE_SOLO_UNA
    /* BISECCION del coste, temporal.  Se forma el paquete igual, se despacha
     * por `L_SLOW` igual y se lee la arena igual, pero se ejecuta SOLO la
     * primera instruccion, como haria el interprete sin paquetes.
     *
     * Si la regresion sigue con esto puesto, el coste esta en LLEGAR aqui
     * (perder el manejador rapido, pasar por L_SLOW, la indireccion de la
     * arena).  Si desaparece, esta en el bucle que ejecuta las k.
     *
     * Es la unica forma de separarlos: entre benchmarks no correlaciona nada.
     */
    {
        /* OJO si se enciende con el reordenamiento puesto: `instr[0]` es la
         * PRIMERA DEL ORDEN DE EJECUCION, que ya no tiene por que ser la de
         * esta direccion (esa es `b->head`).  La biseccion sigue midiendo lo
         * que dice -- ejecutar una sola --, pero no necesariamente la misma. */
        DecodedInstr &ins = b->instr[0];

        *dp = &ins;
        ins.exec_cached(process, ins);
        const bool blocked = ins.flags_info.blocking;
        const bool jumped = ins.flags_info.did_jump;
        process->decoded_ptr = head;
        if (blocked) {
            head->flags_info.blocking = true;
            return;
        }
        if (jumped) {
            *dp = head;
            ins.flags_info.did_jump = false;
            head->flags_info.did_jump = true;
            return;
        }
        rip.qword(rip.raw() + ins.flags_info.size_instr);
        head->flags_info.did_jump = true;
        return;
    }
#endif

    // Bucle con el indice a mano y no un `for`: el desenrollado necesita volver
    // al indice 0, y con `for (...; ++i)` un `i = 0; continue;` saltaria a 1.
    /* Contabilidad de rentabilidad de ESTE paquete cabecera.  Con guarda porque
     * de `exec_bundle` se sale por cinco sitios y el juicio tiene que hacerse
     * en todos: un paquete que solo se midiera al terminar entero nunca se
     * retiraria, porque los que no compensan son justo los que abandonan.
     *
     * Se cobra al paquete de CABECERA aunque se encadene: la pregunta es si
     * merecio la pena entrar por aqui. */
    struct Profit {
        ProcessVM *process;
        Bundle *head_bundle;
        DecodedInstr *entry;
        uint32_t instrs = 0;
        uint32_t entries = 1; ///< esta, mas los encadenados que vengan
        ~Profit() {
            /* Las instrucciones del paquete van al MISMO contador que las del
             * interprete.  El planificador cuenta UNA por despacho, y aqui se
             * despacha una vez y se retiran `instrs`, asi que se le suman las
             * que van de mas.
             *
             * Sin esto la cuenta salia corta justo donde el paquete cunde: un
             * bucle entero recorrido en un solo despacho contaba como una
             * instruccion, y los MIPS bajaban cuanto MEJOR fuera el
             * desenrollado.  Hoy no se nota porque `bundles_on` es false por
             * defecto -- por eso hay que arreglarlo antes de encenderlo, no
             * despues.
             *
             * Va lo PRIMERO del destructor: por debajo hay salidas tempranas
             * (`retired`), y de `exec_bundle` se sale por cinco sitios. */
            if (instrs > 1)
                process->scheduler.profiler_instr_counter += instrs - 1;

            /* Las instrucciones ejecutadas DENTRO de paquetes, una vez por
             * despacho en vez de una por instruccion.  `instrs` ya las lleva
             * contadas -- se incrementa haya telemetria o no --, asi que
             * volver a contarlas en el bucle caliente era pagar dos veces por
             * el mismo dato.  Y esto corre lo PRIMERO del destructor por la
             * misma razon que la linea de arriba: de `exec_bundle` se sale por
             * cinco sitios y hay salidas tempranas mas abajo. */
            BSTAT_ADD(process, instrs_in_bundles, instrs);

            Bundle *hb = head_bundle;

            /* La fusion, PONDERADA POR EJECUCION.  Va aqui y no al final por una
             * razon que costo un reventon: al final, recorrer la icache para
             * leer los paquetes no vale -- una entrada puede seguir diciendo
             * "paquete" con el paquete ya recogido --.  Aqui el paquete se
             * acaba de ejecutar, asi que es seguro por construccion.
             *
             * Y no cuesta: este sitio ya corre una vez por DESPACHO, no por
             * instruccion, con la linea de cache caliente y detras de la misma
             * bandera que el resto de la telemetria.
             *
             * Antes del `retired`, que si no se pierde lo del ultimo tramo. */
            if (__builtin_expect(process->bundle_stats_on, 0)) {
                auto &bs = process->bundle_stats;
                bs.fused_weighted += (uint64_t)hb->fused_pairs * entries;
                bs.newop_ready_weighted += (uint64_t)hb->newop_ready * entries;
                bs.newop_livewall_weighted +=
                    (uint64_t)hb->newop_livewall * entries;
            }

            if (hb->retired) return;
            hb->entries += entries;
            hb->executed += instrs;
            if (hb->entries < Bundle::JUDGE_AFTER) return;
            if (hb->executed / hb->entries >= Bundle::MIN_PER_ENTRY) {
                // Compensa: se reinicia la ventana y se sigue juzgando, por si
                // el comportamiento del sitio cambia mas adelante.
                hb->entries = 0;
                hb->executed = 0;
                return;
            }
            // No compensa.  La entrada de icache vuelve a ser la instruccion
            // original -- que esta guardada intacta en `instr[0]` -- y el
            // interprete la despacha otra vez por su manejador rapido.
            //
            // OJO con `did_jump` y `blocking`: el paquete acaba de ponerlos en
            // la entrada y el run_loop los va a leer NADA MAS volver, para
            // decidir si avanza `rip`.  Restaurar a pelo los borraba, el
            // run_loop avanzaba `rip` una segunda vez y el programa se moria al
            // instante -- salia como un "-100% de tiempo".
            const bool jumped = entry->flags_info.did_jump;
            const bool blocked = entry->flags_info.blocking;
            /* De `head`, no de `instr[0]`: el planificador reordena antes de
             * publicar, asi que en el hueco cero puede haber una instruccion de
             * OTRA direccion.  Ver `Bundle::head`. */
            *entry = hb->head;
            entry->flags_info.did_jump = jumped;
            entry->flags_info.blocking = blocked;
            hb->retired = true;
        }
    } profit{process, b, head};

    /**
     * @brief Nada delegado sobrevive a la salida del despacho.
     *
     * `exec_bundle` vuelve por media docena de sitios -- se bloqueo, salto
     * fuera, se acabaron las reducciones -- y en cuanto vuelve, el planificador
     * puede darle el turno a OTRO proceso.  Si quedara trabajo en vuelo, ese
     * otro veria registros a medio escribir, y eso no da un error: da otro
     * resultado.
     *
     * Va en un destructor y no en cada `return` por eso mismo: un camino de
     * salida que alguien anyada manyana lo hereda gratis.  Y se declara DESPUES
     * de `profit` para destruirse ANTES, porque `profit` lee el estado del
     * proceso para decidir si el paquete compensa.
     *
     * En el caso normal -- reparto apagado, o nada en vuelo -- son dos cargas
     * relajadas y una rama.
     */
    struct DrainGuard {
        ProcessVM *p;
        ~DrainGuard() {
            /* `ooo_exec_dirty` va PRIMERO y es local.  La atomica que sigue la
             * escribe el ayudante, asi que leerla trae su linea de cache: si se
             * mirara siempre, cada despacho pagaria un rebote entre nucleos
             * aunque no se hubiera delegado nada nunca.  Salia en el perfil. */
            /* La cola VACIA es la senyal de que nadie mas esta leyendo memoria
             * de la VM: sin encargos, el ayudante no descodifica ni fusiona.
             * Es el momento exacto en que las tablas de traduccion anteriores
             * se pueden soltar -- la tabla crece duplicandose y guarda la
             * anterior viva por si un lector se quedo dentro --.
             *
             * La condicion barata va PRIMERO y casi siempre es falsa: la
             * cadena solo existe entre que la tabla crece y este momento. */
            if (__builtin_expect(p->vm_mem.has_stale_translation_tables(), 0) &&
                ooo_pending() == 0)
                p->vm_mem.reclaim_translation_tables();

            if (__builtin_expect(p->ooo_exec_dirty, 0) &&
                ooo_exec_inflight()) {
                const uint32_t spins = ooo_drain();
                p->ooo_inflight = ProcessVM::OooInflight{};
                p->ooo_exec_dirty = false;
                if (spins < kOooDrainSlack) {
                    /* Se junto sin esperar: el ayudante ya habia terminado, o
                     * sea que el solape fue completo.  Eso no es una parada,
                     * asi que ni se apunta ni cuenta para la sonda. */
                    return;
                }
                BSTAT(p, ooo_drains);
                /* Y CUENTA para la prueba, igual que la parada por dependencia.
                 *
                 * Sin esto la prueba miraba solo las paradas por choque y no
                 * veia esta, que en los paquetes que no se encadenan es TODAS:
                 * un despacho, una entrega, una espera aqui.  El resultado era
                 * una entrega por parada -- fork-join -- con el contador de
                 * choques a UNO, y la delegacion no se apagaba nunca.  Lo
                 * delato el propio informe: 37.516 paradas y 1 dependencia. */
                ++p->ooo_probe_drains;
            }
        }
    } drain_guard{process};

    uint32_t turns = 0; ///< paquetes encadenados sin soltar el despacho
    uint32_t i = 0;
    // `k` y la base en locales: el bucle las leia a traves del puntero en cada
    // vuelta, y son invariantes salvo cuando el ajuste recorta `k` o se
    // encadena
    // -- los dos sitios las refrescan.
    uint32_t k = b->k;
    DecodedInstr *insts = b->instr;
    // Los dos campos del proceso que el bucle toca en CADA vuelta, en locales.
    // El coste de este bucle esta en NUMERO DE INSTRUCCIONES del host --
    // medido: los paquetes retiran un 41% mas --, no en esperas de memoria, asi
    // que lo que cuenta es quitar accesos, no acercar datos.
    DecodedInstr **const dp = &process->decoded_ptr;
    auto &rip = process->registers.rip;

    /* --- REPARTIR PAQUETES ENTEROS, EN TUBERIA ------------------------------
     *
     * Si este paquete no depende de lo que el ayudante tiene en vuelo y no
     * lleva nada que transfiera control, se le entrega ENTERO y aqui no se
     * ejecuta: solo avanza `rip` y se sigue con el paquete siguiente.  No se
     * espera.
     *
     * Lo que se espera es OTRA cosa: cuando lo que viene SI depende de lo que
     * vuela.  Ahi se vacia la cola.  Esa es toda la diferencia con la version
     * anterior, que esperaba en cada vuelta y por eso no podia ganar --
     * medido: `Serializing Operations` al 100% de los ciclos, 0,755 s
     * esperando contra 0,411 s trabajando, y raciones de 15,9 instrucciones.
     *
     * Se apaga con `VESTA_NO_BUNDLE_OOO`, que es lo que permite medir las dos
     * cosas en la misma maquina y el mismo binario. */
    if (__builtin_expect(process->bundle_ooo_on && !process->ooo_try_exec, 0)) {
        /* Apagado, pero no para siempre: se cuenta hacia el reintento.  Un
         * programa recorre fases y la respuesta cambia con ellas. */
        if (--process->ooo_exec_wait == 0) {
            process->ooo_try_exec = true;
            process->ooo_probe_splits = 0;
            process->ooo_probe_drains = 0;
        }
    }
    /* DELEGAR el paquete que toca ahora, si se puede.  Devuelve true si se
     * fue entero y aqui no queda nada que ejecutar.
     *
     * Es una lambda y no codigo suelto porque hay DOS sitios que la necesitan:
     * al entrar al despacho y al ENCADENAR con el paquete siguiente.  Con solo
     * el primero, un despacho que encadena ocho paquetes delegaba uno y
     * esperaba al final -- una parada por entrega, o sea el fork-join otra vez
     * --, y eso pasaba incluso con material perfectamente independiente: se
     * veia en la mezcla `independ`, hecha justo para descartar esa duda. */
    const auto try_delegate = [&]() -> bool {
        bool delegated = false;
        /* Salir pronto SOLO si no hay nada en vuelo.
         *
         * La comprobacion de choque que viene abajo NO es parte de delegar: es
         * lo que protege a lo que se ejecuta AQUI de pisarse con lo que el
         * ayudante todavia esta haciendo.  Meterla detras del interruptor de
         * la sonda fue un error, y de los que dan otro valor sin fallar: la
         * entrega que apaga la sonda deja un paquete en vuelo, y el siguiente
         * del mismo despacho se ejecutaba sin mirar si chocaba con el.  Salio
         * en `memoria`, que es la mezcla donde chocar es lo normal: `R0 = 0`
         * donde esperaba 30769.
         *
         * Asi que la condicion es "nada que delegar Y nada en vuelo".  Con las
         * dos, esto es una carga local y una rama. */
        if (__builtin_expect(!process->bundle_ooo_on ||
                                 (!process->ooo_try_exec &&
                                  !process->ooo_exec_dirty),
                             1))
            return false;
        const Bundle::Summary &su = b->summary;
        ProcessVM::OooInflight &fly = process->ooo_inflight;

        /* RETIRAR lo que ya termino, ANTES de mirar si choca.
         *
         * El marcador de "en vuelo" solo se limpiaba al vaciar, asi que seguia
         * acusando a un paquete que el ayudante habia terminado hacia rato: el
         * siguiente que tocara uno de sus registros contaba como choque, se
         * vaciaba una cola YA vacia y se apuntaba una parada que no ocurrio.
         *
         * No es un detalle de contabilidad.  La sonda decide por esa
         * proporcion, asi que en la mezcla `independiente` -- donde los grupos
         * de registros se alternan y el tercer paquete vuelve al grupo del
         * primero -- salian 224 entregas y 224 paradas, una por entrega, y el
         * reparto se apagaba solo dandose por inutil.
         *
         * Y se mira SOLO cuando el paquete choca, no en cada paquete.  Esa
         * lectura es de una linea que el AYUDANTE escribe, o sea un viaje al
         * L3 por paquete: en el perfil de hardware las cargas atomicas eran el
         * primer consumidor de tiempo del reparto -- 0,789 s contra 0,226 s de
         * ejecutar --.  Dentro del choque se lee como mucho una vez por
         * dependencia, y es donde cambia algo: sin choque no hay nada que
         * decidir. */

        /* Choca con lo que vuela?  Las tres formas: leer o escribir lo que el
         * otro escribe, escribir lo que el otro lee, y coincidir en un recurso
         * que no se puede desambiguar (los campos implicitos y la memoria de
         * la VM).
         *
         * Y SIN ANALIZAR choca con todo.  No es una precaucion: el resumen de un
         * paquete que nadie ha mirado esta a cero, y cero se lee exactamente
         * igual que "no toca nada" -- incluida la memoria --.  Con la lectura
         * ingenua, un paquete crudo pasaba por aqui diciendo que no chocaba con
         * nada, se rechazaba su delegacion por estar sin analizar, y entonces se
         * EJECUTABA aqui mientras el anterior seguia en vuelo.  En la mezcla
         * `memoria` los dos escriben la misma direccion: `R0 = 0` donde
         * esperaba 30769.
         *
         * Es el mismo agujero que ya obliga a no delegar lo desconocido, y hay
         * que taparlo en los DOS sitios: no poder demostrar que algo es seguro
         * no autoriza a tratarlo como seguro. */
        const bool clash =
            /* Atado a que HAYA algo en vuelo.  Los demas terminos ya salen
             * falsos solos cuando no vuela nada -- sus mascaras estan a cero
             * --, pero este no miraria `fly` en absoluto, y entonces cada
             * paquete crudo vaciaria una cola vacia y apuntaria una parada que
             * no ocurrio.  Eso no rompe nada, pero le mentiria a la sonda, que
             * decide justo por esa proporcion. */
            (process->ooo_exec_dirty &&
             (su.flags & Bundle::SUM_UNKNOWN) != 0) ||
            (((uint16_t)(su.reg_read | su.reg_write) & fly.reg_write) != 0) ||
            ((su.reg_write & fly.reg_read) != 0) ||
            (((uint16_t)(su.vec_read | su.vec_write) & fly.vec_write) != 0) ||
            ((su.vec_write & fly.vec_read) != 0) ||
            ((su.field & fly.field) != 0) ||
            (((su.flags & Bundle::SUM_MEM) != 0) && fly.mem);

        if (clash) {
            /* RETIRAR o VACIAR, y son cosas distintas.
             *
             * Si el ayudante ya termino, el choque no existe: era el marcador
             * el que seguia acusando a un paquete que ya no vuela.  Se limpia y
             * se sigue sin esperar a nadie ni apuntar parada -- contarla apagaba
             * la sonda justo cuando mejor iba --.
             *
             * Y si de verdad esta en vuelo, entonces si toca esperar.  CUANTO
             * se espera es la cifra que dice si esto llego a ser una tuberia;
             * juntarse sin esperar es exactamente lo que se busca. */
            if (!ooo_exec_inflight()) {
                fly = ProcessVM::OooInflight{};
                process->ooo_exec_dirty = false;
            } else {
                const uint32_t spins = ooo_drain();
                fly = ProcessVM::OooInflight{};
                process->ooo_exec_dirty = false;
                BSTAT_IDX(process, ooo_reject, 2);
                if (spins >= kOooDrainSlack) {
                    BSTAT(process, ooo_drains);
                    ++process->ooo_probe_drains;
                }
            }
        }

        /* Y por que NO se delega, cuando no se delega.  Es lo que contesta "no
         * le estamos dando bastante" frente a "no hay nada que dar". */
        if (process->ooo_owner_turn) {
            /* LE TOCA A ESTE HILO.  Se delega uno y se ejecuta uno para que
             * trabajen los dos nucleos; ver `ooo_owner_turn`.  El turno se
             * gasta aqui, al quedarse el paquete, no al ejecutarlo: lo que
             * viene detras de este `return` es el bucle que lo ejecuta. */
            process->ooo_owner_turn = false;
        } else if (!process->ooo_try_exec) {
            /* La sonda dice que aqui no compensa delegar.  Se ha llegado hasta
             * este punto solo por la comprobacion de choque de arriba, que es
             * de correccion y no de rendimiento. */
        } else if ((su.flags & Bundle::SUM_UNKNOWN) != 0) {
            /* Todavia no lo ha mirado nadie -- el analisis va en el ayudante y
             * llega despues --, asi que NO se toca.  Tratarlo como delegable
             * era delegar saltos: la telemetria decia `partibles=0
             * repartidos=5`, cero declarados y cinco delegados. */
            BSTAT_IDX(process, ooo_reject, 5);
        } else if ((su.flags & Bundle::SUM_BARRIER) != 0) {
            BSTAT_IDX(process, ooo_reject, 0);
        } else if ((su.flags & Bundle::SUM_READS_PC) != 0) {
            BSTAT_IDX(process, ooo_reject, 1);
        } else if (ooo_push(process, insts, k)) {
            /* Se va entero.  Aqui solo avanza `rip` -- de una vez, porque nada
             * de lo delegado lo lee -- y la cuenta de instrucciones. */
            for (uint32_t j = 0; j < k; ++j) {
                rip.qword(rip.raw() + insts[j].flags_info.size_instr);
                profit.instrs += 1u + insts[j].flags_info.absorbed;
            }
            fly.reg_read = (uint16_t)(fly.reg_read | su.reg_read);
            fly.reg_write = (uint16_t)(fly.reg_write | su.reg_write);
            fly.vec_read = (uint16_t)(fly.vec_read | su.vec_read);
            fly.vec_write = (uint16_t)(fly.vec_write | su.vec_write);
            fly.field = (uint8_t)(fly.field | su.field);
            fly.mem = fly.mem || ((su.flags & Bundle::SUM_MEM) != 0);
            process->ooo_exec_dirty = true;

            BSTAT(process, ooo_split);
            BSTAT_ADD(process, ooo_delegated, k);
            delegated = true;                 // nada que ejecutar aqui
            process->ooo_owner_turn = true;   // el siguiente es para este hilo

            /* Y la PRUEBA: esto sirve o solo estorba?
             *
             * Si casi todas las entregas acabaron obligando a una parada, no
             * hay tuberia -- es un fork-join con otro nombre -- y se deja de
             * intentar.  El analisis se le sigue dando igual, que ese no
             * depende de nada.
             *
             * Se mide en vez de decidirlo por adelantado porque la respuesta
             * es del PROGRAMA, no del mecanismo: un bucle sobre un acumulador
             * no tiene dos paquetes independientes seguidos, y otro codigo
             * puede tenerlos. */
            if (++process->ooo_probe_splits >= ProcessVM::kOooProbe) {
                // Nueve de cada diez: por debajo de eso todavia hay tuberia.
                if (process->ooo_probe_drains * 10u <
                    process->ooo_probe_splits * 9u) {
                    // Compensa: el proximo reintento vuelve a ser corto.
                    process->ooo_exec_backoff = 0;
                } else {
                    process->ooo_try_exec = false;
                    process->ooo_exec_backoff =
                        process->ooo_exec_backoff == 0
                            ? ProcessVM::kOooRetry
                            : (process->ooo_exec_backoff <
                                       ProcessVM::kOooRetryMax / 2
                                   ? process->ooo_exec_backoff * 2
                                   : ProcessVM::kOooRetryMax);
                    process->ooo_exec_wait = process->ooo_exec_backoff;
                }
                process->ooo_probe_splits = 0;
                process->ooo_probe_drains = 0;
            }
        } else {
            /* La cola estaba llena o el ayudante lo tiene otro proceso.  Las
             * dos se apuntan aparte: "llena" significa que el ayudante no da
             * abasto, que es un problema MUY distinto de no encontrar trabajo
             * independiente. */
            BSTAT_IDX(process, ooo_reject,
                      ooo_pending() >= kOooSlots ? 3u : 4u);
        }

        return delegated;
    };

    /* Delegado el paquete, se SIGUE con el siguiente sin soltar el despacho.
     *
     * Es lo que convierte esto en una tuberia.  Sin ello, delegar terminaba el
     * despacho -- el principal ya no ejecutaba la ultima instruccion del
     * paquete, asi que no veia ningun salto y no encadenaba -- y al volver el
     * guardia esperaba: una entrega y una parada, el fork-join de siempre con
     * otro nombre.  Pasaba INCLUSO con material perfectamente independiente,
     * que es justo lo que la mezcla `independiente` esta hecha para distinguir.
     *
     * Se intento antes y daba valores incorrectos, pero la causa NO era esto:
     * era que un paquete sin analizar tenia el resumen a cero y cero se lee
     * igual que "no toca nada", asi que pasaba la comprobacion de choque
     * diciendo que no chocaba con nada y se ejecutaba aqui mientras el anterior
     * seguia en vuelo.  Con `SUM_UNKNOWN` chocando contra todo, eso ya no pasa.
     *
     * Los topes son los del encadenado normal: ni mas vueltas que
     * `BUNDLE_LOOP_MAX`, ni gastar mas reducciones de las que quedan.  Un
     * despacho que no suelta el turno deja sin correr a los demas. */
    bool gone = false;
    for (;;) {
        if (!try_delegate()) break; // este no se va: se ejecuta aqui abajo
        gone = true;
        if (turns >= BUNDLE_LOOP_MAX ||
            process->reductions_remaining <= b->k)
            break;
        DecodedInstr *next = icache_lookup(process, rip.raw());
        if (next == nullptr || next->metadata != &g_bundle_format) break;
        ++turns;
        ++profit.entries;
        BSTAT(process, chained);
        process->reductions_remaining -= b->k;
        b = bundle_of(*next);
        k = b->k;
        insts = b->instr;
        gone = false; // el nuevo todavia no se ha ido
    }
    if (gone) i = k; // nada que ejecutar: el bucle de abajo no entra

    /* POR QUE ESTE BUCLE NO SE ENVUELVE EN OTRO.
     *
     * Se intento seguir por el paquete siguiente sin soltar el despacho
     * mientras hubiera trabajo en vuelo, para que la juntada con el ayudante se
     * pagara una vez por muchos paquetes en vez de una por cada dos.  Funciona
     * -- las paradas por entrega bajaron de 0,26 a 0,08 --, pero envolver este
     * bucle en otro le cuesta el mundo al motor que SI gana, porque `i`, `k`,
     * `insts` y `b` pasan a estar vivos entre vueltas de la envoltura y dejan
     * de vivir en registros.  Medido, y no es un matiz:
     *
     *     alu:260:paquetes       350,4  ->  296,6   (-16%)
     *     mixta:1024:paquetes    316,8  ->  246,7   (-21%)
     *     memoria:256:paquetes   336,2  ->  314,7   (-6,5%)
     *
     * O sea: se le cobraba hasta un 21% al camino bueno para amortizar una
     * espera del reparto, que aun asi sigue perdiendo.  No compensa.  Si algun
     * dia hace falta, el sitio es una funcion aparte que vuelva a entrar, no
     * una envoltura alrededor del bucle por instruccion. */
    while (i < k) {
        DecodedInstr &ins = insts[i];
        // La siguiente son otros 64 bytes, o sea OTRA linea de cache.  Un
        // paquete de 32 recorre 32 lineas, y el perfil dice que leer la
        // instruccion es la linea mas cara del bucle (0,335 s de 2,44).
        // Pedirla mientras se ejecuta esta la trae sin esperar.
        if (i + 1 < k) __builtin_prefetch(&insts[i + 1], 0, 3);

        // `decoded_ptr` tiene que apuntar a la instruccion que se esta
        // ejecutando de verdad y no a la cabecera: los manejadores lo usan para
        // marcar `did_jump`, y `build_stack_trace` lo lee para decir donde se
        // murio el programa.  Sin esto, un fallo dentro del paquete senalaria
        // siempre a la primera instruccion.
        // `ins.pc` ya viene puesto DESDE LA FORMACION: escribirlo aqui costaba
        // una escritura a la arena por instruccion (0,272 s de 2,44 en el
        // perfil) y ademas leia de `original_pc`, que era un array APARTE --
        // una segunda linea de cache por paquete para un dato que no cambia
        // nunca.
        *dp = &ins;

#if BUNDLE_DIRECT_CALL
        /* Llamada DIRECTA para los opcodes mas frecuentes.
         *
         * Medido con VTune: los paquetes retiran un 41% mas de instrucciones
         * del host, y el grueso es el coste por instruccion del bucle -- no
         * memoria (`Memory Bound` BAJA con paquetes) ni prediccion
         * (`Bad Speculation` cae del 40% a 0%).
         *
         * Un `call` por puntero obliga a cargar el destino y no se puede
         * inlinar.  Comparando primero contra los manejadores mas usados, el
         * compilador emite una llamada directa -- y si algun dia el cuerpo es
         * visible, la puede inlinar.
         *
         * Va tras una macro para poder contrastarlo: es una lista de opcodes
         * elegida por frecuencia, o sea algo que envejece, y hay que poder
         * medir si sigue compensando. */
        const auto f = ins.exec_cached;
        if (f == &exec_instr_mov_reg)
            exec_instr_mov_reg(process, ins);
        else if (f == &exec_instr_alu3)
            exec_instr_alu3(process, ins);
        else if (f == &exec_instr_jmp)
            exec_instr_jmp(process, ins);
        else
            f(process, ins);
#else
        ins.exec_cached(process, ins);
#endif
        /* Sin `BSTAT` aqui: esto es el bucle POR INSTRUCCION, y una rama por
         * instruccion ejecutada se nota -- medido, 17% en las filas de
         * paquetes del banco --.  El contador se deriva al salir, de
         * `profit.instrs`, que ya lleva exactamente la misma cuenta y se
         * incrementa igual haya telemetria o no.  Contar dos veces lo mismo,
         * una de ellas en el sitio caro, era el error. */
        profit.instrs += 1u + ins.flags_info.absorbed;

        const bool blocked = ins.flags_info.blocking;
        const bool jumped = ins.flags_info.did_jump;
        // `decoded_ptr` NO se restaura aqui.  Mientras el paquete corre tiene
        // que apuntar a la instruccion en curso -- es lo que lee la traza de un
        // fallo --, y restaurarlo en cada vuelta era otra escritura por
        // instruccion (0,213 s) para dejarlo como estaba justo antes de
        // volverlo a cambiar.  Se restaura UNA vez, al salir.

        if (blocked) {
            *dp = head;
            // Se bloqueo: no se avanza `rip` y hay que reejecutar cuando se
            // resuelva.  Se propaga a la cabecera para que el run_loop lo vea.
            head->flags_info.blocking = true;
            BSTAT(process, aborts);
            return;
        }
        if (jumped) {
            *dp = head;
            ins.flags_info.did_jump = false;

            // ENCADENADO.  Si el destino del salto es la cabecera de otro
            // paquete, se sigue por el sin soltar el despacho.
            //
            // La version anterior solo miraba si el salto volvia a la cabecera
            // de ESTE paquete, y no disparaba nunca: un bucle no suele caber en
            // un paquete.  El de `tight_loop` son DOS que se llaman entre si --
            // 0x34 salta a 0xa8 y 0xa8 vuelve a 0x34 --, asi que ninguno
            // regresa a su propia cabecera.  Encadenando, el bucle entero se
            // recorre en un solo despacho, y eso ES el desenrollado: el tramo
            // deja de valer lo que el cuerpo del bucle.
            //
            // Sigue sin predecirse nada: se mira el destino REAL ya ejecutado.
            // Si el bucle sale, ahi no habra cabecera de paquete o sera otra, y
            // se encadena o se abandona segun toque -- las dos cosas correctas.
            if (turns < BUNDLE_LOOP_MAX &&
                process->reductions_remaining > b->k) {
                DecodedInstr *next =
                    icache_lookup(process, process->registers.rip.raw());
                if (next != nullptr && next->metadata == &g_bundle_format) {
                    ++turns;
                    ++profit.entries;
                    BSTAT(process, chained);
                    // Se descuentan las reducciones que consume el paquete
                    // encadenado.  Sin esto, un bucle largo se quedaria dentro
                    // sin dar turno a nadie: el planificador cuenta despachos,
                    // y aqui se ejecuta sin gastarlos.
                    process->reductions_remaining -= b->k;
                    b = bundle_of(*next);
                    k = b->k;
                    insts = b->instr;
                    /* El encadenado tambien delega.  Aqui es donde la tuberia
                     * se forma de verdad: un despacho recorre varios paquetes,
                     * y si solo se mirara al entrar se delegaria uno y se
                     * esperaria al salir. */
                    i = try_delegate() ? k : 0;
                    continue;
                }
            }

            // Se fue a otro sitio: el resto del paquete NO le corresponde a
            // este flujo.  `rip` ya lo dejo puesto la instruccion.
            head->flags_info.did_jump = true;
            BSTAT(process, aborts);

            // Ajuste de k: si siempre se corta aqui, es que esta instruccion
            // salta y las de detras no se ejecutan nunca desde este paquete.
            // Recortar deja de descodificarlas al reformar y hace que el
            // paquete termine justo en el salto.  Se espera a que se repita
            // para no encoger por un condicional que unas veces salta y otras
            // no -- esas veces el resto SI se ejecuta.
            if (i + 1 < b->k) {
                if (b->abort_at == i) {
                    if (++b->abort_runs >= Bundle::ABORT_SETTLE) {
                        b->k = i + 1;
                        k = b->k;
                        b->abort_runs = 0;
                        BSTAT(process, shrinks);
                    }
                } else {
                    b->abort_at = i;
                    b->abort_runs = 1;
                }
            }
            return;
        }

        rip.qword(rip.raw() + ins.flags_info.size_instr);
        ++i;
    }

    // Todas ejecutadas y `rip` ya avanzado por el paquete.  Se marca `did_jump`
    // para que el run_loop NO vuelva a avanzarlo: no es que se haya saltado, es
    // que el avance ya esta hecho.  Hace falta porque `size_instr` son 4 BITS y
    // el tamano total de un paquete se pasa de 15 en cuanto hay dos
    // instrucciones largas.
    process->decoded_ptr = head;
    head->flags_info.did_jump = true;
}

} // namespace runtime

#endif // VM_BUNDLES
