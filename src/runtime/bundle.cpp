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
#include "runtime/exec_instruction.h"

namespace runtime {

namespace {

#if VM_BUNDLE_STATS
#define BSTAT(p, field) (++(p)->bundle_stats.field)
#else
/* Sin telemetria no queda ni la suma: medir el coste no puede cambiar lo que se
 * mide. */
#define BSTAT(p, field) ((void)0)
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

void bundle_release(ProcessVM *process) {
    delete static_cast<BundleArena *>(process->bundle_arena);
    process->bundle_arena = nullptr;
}

void bundle_try_form(ProcessVM *process, DecodedInstr *slot, uint64_t pc) {
    if (!process->bundles_on) return;

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

    BundleArena *arena = arena_of(process);
    if (arena->total >= BundleArena::CAPACITY) {
        // Llena.  No se puede vaciar aqui sin invalidar la icache -- sus
        // entradas de paquete apuntarian a indices muertos --, asi que
        // simplemente se deja de formar.  Reciclar exige vaciar las dos a la
        // vez, y ese es el mismo camino que la invalidacion por codigo nuevo.
        BSTAT(process, flushes);
        return;
    }

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
        }
        ~Pin() { p->icache_pinned = nullptr; }
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
        Bundle *head_bundle;
        DecodedInstr *entry;
        uint32_t instrs = 0;
        uint32_t entries = 1; ///< esta, mas los encadenados que vengan
        ~Profit() {
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
    } profit{b, head};

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
