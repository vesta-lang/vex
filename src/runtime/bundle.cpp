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

#include "runtime/bundle.h"

#if VM_BUNDLES

#include "bytecode/bytecode.h"
#include "runtime/decode_instruction.h"
#include "disasm/disasm.h" // asm real en los volcados de la cache
#include "runtime/instr_db_vm.h" // nombre del opcode en los volcados
#include "util/env_flags.h" // VESTA_CACHE_DUMP: volcado del estado de caches
#include "runtime/exec_instruction.h"

namespace runtime {

namespace {

#if VM_BUNDLE_STATS
#define BSTAT(p, field) (++(p)->bundle_stats.field)
/* Suma una cantidad en vez de uno: hace falta para lo que no se cuenta por
 * veces sino por unidades -- cuantas instrucciones cambiaron de sitio --.
 *
 * OJO: sin telemetria el argumento SE SIGUE EVALUANDO, y tiene que ser asi.
 * Ahi dentro va la llamada que hace el trabajo, no solo la que produce el
 * numero; que la cuenta desaparezca no puede hacer desaparecer el reorden. */
#define BSTAT_ADD(p, field, n) ((p)->bundle_stats.field += (n))
#else
/* Sin telemetria no queda ni la suma: medir el coste no puede cambiar lo que se
 * mide. */
#define BSTAT(p, field) ((void)0)
#define BSTAT_ADD(p, field, n) ((void)(n))
#endif

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
    if (p->bundle_arena == nullptr) p->bundle_arena = new BundleArena();
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
#if VM_BUNDLE_STATS
    /* La telemetria de paquetes existia y NO LA IMPRIMIA NADIE: los contadores
     * se llenaban y morian con el proceso.  Una medida que no se puede leer no
     * es una medida, asi que se vuelca aqui, que es donde el proceso termina.
     *
     * Va dentro del mismo `#if` que los incrementos: con la telemetria apagada
     * -- que es el defecto -- esto no existe, igual que ellos. */
    const auto &s = process->bundle_stats;
    if (s.dispatches != 0 || s.formed != 0) {
        std::fprintf(
            stderr,
            "\n[paquetes] formados=%llu no_formados=%llu aplazados=%llu "
            "recolecciones=%llu\n"
            "           despachos=%llu instr_dentro=%llu  -> %.1f por despacho\n"
            "           abandonos=%llu encogidos=%llu encadenados=%llu\n"
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
            (unsigned long long)s.chained, (unsigned long long)s.reordered,
            s.instrs_in_bundles
                ? 100.0 * (double)s.reordered / (double)s.instrs_in_bundles
                : 0.0,
            (unsigned long long)s.reorder_bundles,
            (unsigned long long)s.reorder_wins[0],
            (unsigned long long)s.reorder_wins[1],
            (unsigned long long)s.reorder_wins[2],
            (unsigned long long)s.reorder_wins[3],
            (unsigned long long)s.reorder_choices);
    }
#endif
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
    Bundle b;
    b.k = 1;
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
        // la arena para no ahorrar ni un despacho.
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
    /* REORDENAR antes de publicar.  Aqui y no al ejecutar: se paga una vez por
     * sitio y se cobra en cada una de las miles de entradas siguientes.
     *
     * Se hace sobre `b`, que todavia es local: si algo saliera mal, el paquete
     * que se publica es el que ya estaba bien formado. */
    if (__builtin_expect(process->bundle_reorder_on &&
                             !::util::flag_on(::util::FlagId::NoBundleReorder),
                         1))
        BSTAT_ADD(process, reordered, bundle_reorder(process, b));

    Bundle *rec = arena->alloc();
    *rec = b;

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

            Bundle *hb = head_bundle;
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
            *entry = hb->instr[0];
            entry->flags_info.did_jump = jumped;
            entry->flags_info.blocking = blocked;
            hb->retired = true;
        }
    } profit{process, b, head};

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
        BSTAT(process, instrs_in_bundles);
        ++profit.instrs;

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
                    i = 0;
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
