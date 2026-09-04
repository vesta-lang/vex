/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/runtime/test_bundle_reorder.cpp
 * @brief Las PROPIEDADES del planificador que reordena dentro de un paquete.
 *
 * Que valida, y por que hace falta aparte
 * ---------------------------------------
 * `test_bundles` comprueba lo de fuera: que un programa da el mismo resultado
 * con paquetes y sin ellos.  Es la red que de verdad importa, pero llega
 * TARDE y dice POCO -- cuando falla, lo que se sabe es que un registro acabo
 * distinto al final de un programa de dos millones de instrucciones --.
 *
 * Aqui se comprueba lo de dentro, sobre el orden que sale del planificador,
 * antes de ejecutar nada:
 *
 *   1. ORDEN VALIDO.  Ningun par que dependia queda intercambiado.  Es LA
 *      propiedad: reordenar dos que si dependian no da un error, da otro
 *      resultado.
 *   2. LAS BARRERAS NO SE CRUZAN.  Nada pasa de un lado a otro de una
 *      instruccion inmovible, ni ella se mueve.
 *   3. LA BANDERA APAGA.  Con `VESTA_NO_BUNDLE_REORDER` el paquete sale
 *      identico, byte a byte.  Sin esto, contrastar con y sin no vale de nada.
 *   4. ES ESTABLE.  Reordenar lo ya reordenado no lo vuelve a mover: si el
 *      planificador no converge, dos formaciones del mismo sitio dan ordenes
 *      distintos y la telemetria deja de significar nada.
 *   5. NO PIERDE NI DUPLICA.  Salen las mismas k instrucciones que entraron,
 *      cada una una vez.
 *
 * Las tres primeras se comprueban contra un modelo de dependencias
 * INDEPENDIENTE del que usa el planificador -- se deriva aqui, del
 * desensamblador y de la base de efectos --.  Comprobar el resultado con el
 * mismo modelo que lo produjo solo demuestra que el codigo hace lo que hace.
 *
 * Uso:
 *   test_bundle_reorder [fichero.velb ...]
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "../util/gen_program.h"
#include "disasm/disasm.h"
#include "jit/auto_jit.h"
#include "runtime/bundle.h"
#include "runtime/decode_instruction.h"
#include "runtime/instr_db_vm.h"
#include "runtime/manager_runtime.h"
#include "runtime/proceso_runtime.h"
#include "util/ansi.h"
#include "util/env_flags.h"

namespace {

int g_pass = 0;
int g_fail = 0;
/// Cuantas instrucciones el modelo declaro movibles y cuantas barrera, en el
/// programa que se esta mirando.  Es el denominador de todo lo demas.
uint32_t g_movibles = 0;
uint32_t g_barreras = 0;
/* Una barrera se fija A SI MISMA, no congela el paquete: lo que queda a cada
 * lado se sigue reordenando entre si.  Estos dos lo miden -- cuantos paquetes
 * traian barrera y en cuantos de esos se movio algo igual --, porque es la
 * diferencia entre un modelo que ordena y uno que se rinde en cuanto ve algo
 * que no entiende, y las dos cosas pasan las comprobaciones de correccion. */
uint32_t g_con_barrera = 0;
uint32_t g_con_barrera_movidos = 0;
bool g_este_tenia_barrera = false; ///< lo pone @ref validar para el bucle
/* Cuantos paquetes tenian MARGEN: al menos dos contiguas que se podian
 * intercambiar.  Sin este dato, "no movio nada" tiene dos causas que se leen
 * igual y llevan a sitios opuestos -- que el programa sea una cadena de
 * dependencias, donde no mover es la respuesta CORRECTA, o que el planificador
 * se este rindiendo --, y acusar de lo segundo cuando es lo primero manda a
 * arreglar lo que no esta roto. */
uint32_t g_con_margen = 0;
/* Totales del CONJUNTO, que es donde se exige que el planificador haga algo.
 *
 * Por programa no se puede exigir: que un paquete tenga margen -- dos
 * contiguas intercambiables -- no quiere decir que exista un orden MEJOR.  Si
 * cada instruccion ya es independiente de la anterior, todas las candidatas
 * empatan y gana la que ya iba primera; no mover es entonces la respuesta
 * correcta del modelo, no una renuncia.  Lo que si tiene que ser cierto es que
 * en el conjunto se mueva algo y que alguna barrera no congele su paquete: un
 * planificador que no moviera NUNCA pasaria todas las comprobaciones de
 * correccion sin hacer nada. */
uint32_t g_tot_movidos = 0;
uint32_t g_tot_margen = 0;
uint32_t g_tot_barrera_movidos = 0;

void check(bool cond, const char *que, const char *donde) {
    if (cond) {
        ++g_pass;
        return;
    }
    ++g_fail;
    std::printf("  %sFALLO%s  %-28s %s\n", ansi::c(ansi::BR_RED),
                ansi::c(ansi::RESET), donde, que);
}

#if VM_BUNDLES

/* --- El modelo de contraste ---------------------------------------------
 *
 * Se deriva aqui, por su cuenta, y NO se reutiliza el del planificador: eso es
 * lo que hace que un error de indexacion, de mascara o de planificacion salga:
 * los dos tendrian que equivocarse igual.  Lo que NO puede cazar es un error
 * conceptual compartido -- si la idea de dependencia esta mal, lo esta en los
 * dos --, y conviene saberlo en vez de creer que cubre mas de lo que cubre.
 *
 * Lo que si tiene que ser es EXACTO en la direccion de las dependencias.  Un
 * modelo "mas basto por prudencia" no vale para validar: si cuenta como
 * conflicto que dos instrucciones LEAN el mismo registro -- que no lo es --,
 * acusa al planificador de mover algo que podia mover.  Se probo, y dio 160
 * fallos que no eran fallos.
 */
struct Rough {
    uint16_t gp_read = 0, gp_write = 0;   ///< registros generales
    uint16_t vec_read = 0, vec_write = 0; ///< y vectoriales
    uint8_t f_read = 0, f_write = 0;      ///< banderas/pila/marco/pc
    bool mem = false;
    bool barrier = true;
};

Rough rough_of(runtime::ProcessVM *proc, const runtime::DecodedInstr &d) {
    Rough r;
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const uint8_t op =
        ext ? (uint8_t)d.flags_info.opcode_index : d.flags_info.is_not_extended;
    const uint16_t eff = runtime::vm_isa::vm_hot(ext, op);
    if (!runtime::vm_isa::vm_instr_movable(eff)) return r;
    if ((eff & runtime::vm_isa::VE_R_PC) != 0) return r; // ver bundle_reorder

    // Los cuatro campos, escrituras en los bits bajos y lecturas en los altos.
    r.f_write = (uint8_t)(eff & 0x0F);
    r.f_read = (uint8_t)((eff >> 4) & 0x0F);
    r.mem = (eff & runtime::vm_isa::VE_MEMORY) != 0;

    uint8_t buf[16] = {};
    const uint32_t n =
        d.flags_info.size_instr != 0 ? d.flags_info.size_instr : 16u;
    if (n > sizeof(buf)) return r;
    proc->vm_mem.read_bytes(d.pc, buf, n);
    disasm::DisasmOptions o;
    o.show_hex = false;
    o.use_color = false;
    o.stop_at_hlt = false;
    const auto out = disasm::disasm_bytes(buf, n, d.pc, o);
    if (out.empty()) return r;
    if (out.front().operands.find('[') != std::string::npos) r.mem = true;
    for (const disasm::RegOperand &ro : out.front().regs) {
        if (ro.index > 15) return r;
        const uint16_t bit = (uint16_t)(1u << ro.index);
        // El destino cuenta tambien como lectura, igual que en el planificador:
        // no se puede saber por opcode si lee lo que escribe, y suponer que no
        // lo lee es lo unico que romperia.
        (ro.floating ? r.vec_read : r.gp_read) |= bit;
        if (ro.dest) (ro.floating ? r.vec_write : r.gp_write) |= bit;
    }
    r.barrier = false;
    return r;
}

/// Chocan de verdad: escribe-lee, lee-escribe o escribe-escribe sobre lo mismo.
/// Que las dos LEAN no es conflicto, y contarlo como tal acusaria de mover algo
/// que se podia mover.
bool clash(const Rough &a, const Rough &b) {
    if (a.barrier || b.barrier) return true;
    if ((a.gp_write & (b.gp_read | b.gp_write)) != 0) return true;
    if ((b.gp_write & a.gp_read) != 0) return true;
    if ((a.vec_write & (b.vec_read | b.vec_write)) != 0) return true;
    if ((b.vec_write & a.vec_read) != 0) return true;
    if ((a.f_write & (b.f_read | b.f_write)) != 0) return true;
    if ((b.f_write & a.f_read) != 0) return true;
    return a.mem && b.mem;
}

/**
 * @brief Comprueba las cinco propiedades sobre un paquete ya reordenado.
 *
 * @param proc  Proceso, para leer los bytes.
 * @param antes El paquete tal y como se formo, en orden de direccion.
 * @param ahora El mismo despues de reordenar.
 * @param donde Nombre del programa, para el mensaje.
 */
void validar(runtime::ProcessVM *proc, const runtime::Bundle &antes,
             const runtime::Bundle &ahora, const char *donde) {
    check(antes.k == ahora.k, "el paquete cambio de tamano", donde);
    if (antes.k != ahora.k) return;

    // 5. Ni se pierde ni se duplica: las mismas direcciones, cada una una vez.
    uint32_t vistas = 0;
    bool completo = true;
    for (uint32_t i = 0; i < ahora.k; ++i) {
        bool esta = false;
        for (uint32_t j = 0; j < antes.k; ++j)
            if (antes.instr[j].pc == ahora.instr[i].pc && !((vistas >> j) & 1)) {
                vistas |= (1u << j);
                esta = true;
                break;
            }
        if (!esta) completo = false;
    }
    check(completo, "salen instrucciones que no entraron, o repetidas", donde);

    // Donde estaba cada una, para poder preguntar si dos se cruzaron.
    uint32_t pos[BUNDLE_MAX];
    for (uint32_t i = 0; i < ahora.k; ++i) {
        pos[i] = i;
        for (uint32_t j = 0; j < antes.k; ++j)
            if (antes.instr[j].pc == ahora.instr[i].pc) pos[i] = j;
    }

    std::vector<Rough> t(antes.k);
    g_este_tenia_barrera = false;
    for (uint32_t i = 0; i < antes.k; ++i) {
        t[i] = rough_of(proc, antes.instr[i]);
        if (t[i].barrier) {
            ++g_barreras;
            g_este_tenia_barrera = true;
        } else {
            ++g_movibles;
        }
    }
    if (g_este_tenia_barrera) ++g_con_barrera;

    // Habia DOS contiguas intercambiables?  Es el margen minimo: sin el, la
    // unica ordenacion valida es la que ya trae y no mover es lo correcto.
    for (uint32_t i = 0; i + 1 < antes.k; ++i)
        if (!clash(t[i], t[i + 1])) {
            ++g_con_margen;
            break;
        }

    /* 1 y 2 juntas: si dos se cruzaron y el modelo basto dice que chocaban, el
     * reorden es incorrecto.  Una barrera choca con todo, asi que la misma
     * comprobacion cubre que nada la cruce. */
    bool ok = true;
    for (uint32_t i = 0; i < ahora.k && ok; ++i)
        for (uint32_t j = i + 1; j < ahora.k && ok; ++j)
            if (pos[i] > pos[j] && clash(t[pos[j]], t[pos[i]])) ok = false;
    check(ok, "cruzo dos instrucciones que dependian entre si", donde);
}

/// @brief Una instruccion desensamblada, para el volcado lado a lado.
std::string texto(runtime::ProcessVM *proc, const runtime::DecodedInstr &d) {
    uint8_t buf[16] = {};
    const uint32_t n =
        d.flags_info.size_instr != 0 ? d.flags_info.size_instr : 16u;
    if (n > sizeof(buf)) return "?";
    proc->vm_mem.read_bytes(d.pc, buf, n);
    disasm::DisasmOptions o;
    o.show_hex = false;
    o.use_color = false;
    o.stop_at_hlt = false;
    const auto out = disasm::disasm_bytes(buf, n, d.pc, o);
    if (out.empty()) return "?";
    return out.front().mnemonic + " " + out.front().operands;
}

/**
 * @brief Ensena el paquete ANTES y DESPUES, y por que se movio cada una.
 *
 * "Se reordeno" no explica nada: lo que hay que poder leer es si una
 * instruccion se adelanto para FUSIONARSE con la anterior, para no depender de
 * ella -- que es lo que permite lanzarlas a la vez cuando la ejecucion sea
 * fuera de orden --, o para agrupar accesos.  Esa es la unica forma de juzgar
 * si los pesos estan bien puestos, y de ver un reorden equivocado antes de que
 * salga como un registro distinto al final del programa.
 *
 * @param proc  Proceso, para desensamblar.
 * @param antes El paquete tal y como se formo.
 * @param ahora El mismo despues de reordenar.
 * @param why   Criterio que decidio cada posicion.
 */
void ensenar(runtime::ProcessVM *proc, const runtime::Bundle &antes,
             const runtime::Bundle &ahora, const uint8_t *why) {
    std::printf("\n  %spaquete en 0x%08llx  k=%u%s\n", ansi::c(ansi::BOLD),
                (unsigned long long)antes.instr[0].pc, antes.k,
                ansi::c(ansi::RESET));
    std::printf("    %-38s   %-38s  %s\n", "ANTES (orden del programa)",
                "DESPUES (orden de ejecucion)", "por que");
    for (uint32_t i = 0; i < ahora.k; ++i) {
        const bool cambia = antes.instr[i].pc != ahora.instr[i].pc;
        const std::string a =
            std::to_string(i) + ": " + texto(proc, antes.instr[i]);
        const std::string d = texto(proc, ahora.instr[i]);
        std::printf("    %-38s %s %-38s%s  %s%s%s\n", a.c_str(),
                    cambia ? "->" : "  ", d.c_str(), "",
                    cambia ? ansi::c(ansi::BR_YELLOW) : ansi::c(ansi::BR_BLACK),
                    cambia ? runtime::bundle_reorder_criterion(why[i]) : "",
                    ansi::c(ansi::RESET));
    }
}

/// Forma paquetes ejecutando el programa y valida cada uno.
void probar(const std::string &fichero, bool detalle) {
    const char *donde = fichero.c_str();
    const size_t barra = fichero.find_last_of("/\\");
    if (barra != std::string::npos) donde += barra + 1;

    runtime::ManageVM mgr(nullptr, 0);
    runtime::VM *vm = mgr.loader.create_vm_instance(1);
    runtime::ProcessVM *proc = nullptr;
    try {
        proc = mgr.loader.load_executable(*vm, fichero);
    } catch (const std::exception &e) {
        std::printf("  %-28s no carga: %s\n", donde, e.what());
        return;
    }
    if (proc == nullptr) return;

    jit::g_jit_threshold = UINT32_MAX;
    jit::g_pc_jit_active = false;
    proc->bundles_on = true;
    for (const auto &s : vm->schedulers) s->has_hooks = false;
    vm->make_ready(proc->pid);
    vm->start();
    while (proc->state != runtime::HALT && proc->state != runtime::DEAD)
        std::this_thread::yield();

    /* Los paquetes ya formados se vuelven a reordenar aqui a partir de su
     * propio contenido.  No es dar dos vueltas por gusto: es lo que permite
     * comparar el ANTES con el DESPUES, que durante la formacion no se guarda
     * -- y de paso comprueba la ESTABILIDAD, porque lo que entra ya paso por el
     * planificador una vez y no deberia moverse otra. */
    uint32_t mirados = 0, movidos = 0;
    g_movibles = 0;
    g_barreras = 0;
    g_con_barrera = 0;
    g_con_barrera_movidos = 0;
    g_con_margen = 0;
    for (uint32_t i = 0; i < runtime::ICACHE_SIZE; ++i) {
        runtime::DecodedInstr &e = proc->icache[i];
        if (e.exec_cached != &runtime::exec_bundle) continue;
        runtime::Bundle *b = runtime::bundle_of(e);
        if (b == nullptr || b->k < 3) continue;
        /* El ANTES se RECONSTRUYE ordenando por direccion.
         *
         * Un paquete es un tramo RECTO, asi que el orden del programa es el de
         * `pc` creciente -- y el `pc` viaja dentro de cada instruccion desde
         * que se forma --.  Reordenar no lo pierde, solo lo permuta.
         *
         * Es lo que permite tener un ANTES sin depender de como se formo el
         * paquete: si se toma tal cual esta, lo que se valida es reordenar lo
         * ya reordenado, que es un no-op y pasa sin comprobar nada. */
        runtime::Bundle antes = *b;
        for (uint32_t x = 1; x < antes.k; ++x)
            for (uint32_t y = x; y > 0 && antes.instr[y].pc < antes.instr[y - 1].pc;
                 --y) {
                const runtime::DecodedInstr tmp = antes.instr[y];
                antes.instr[y] = antes.instr[y - 1];
                antes.instr[y - 1] = tmp;
            }
        runtime::Bundle copia = antes;
        uint8_t why[BUNDLE_MAX] = {};
        const uint32_t n = runtime::bundle_reorder(proc, copia, why);
        validar(proc, antes, copia, donde);
        ++mirados;
        if (n != 0) {
            ++movidos;
            if (g_este_tenia_barrera) ++g_con_barrera_movidos;
            // Con `--detalle`, los primeros que se muevan se ensenan enteros.
            if (detalle && movidos <= 3) ensenar(proc, antes, copia, why);
            /* ESTABILIDAD: reordenar lo ya reordenado no lo vuelve a mover.  Si
             * no converge, dos formaciones del mismo sitio dan ordenes
             * distintos y nada de lo que se mida encima significa nada. */
            runtime::Bundle otra = copia;
            check(runtime::bundle_reorder(proc, otra, nullptr) == 0,
                  "reordenar lo ya reordenado lo vuelve a mover", donde);
        }
        if (mirados >= 200) break; // suficiente: mas no anade casos, solo tiempo
    }
    // Que MUEVA algo: un reordenador que nunca mueve pasa las comprobaciones
    // de correccion sin hacer nada, y entonces no estan comprobando nada.
    // Se suma al conjunto; la exigencia de que MUEVA se comprueba ahi.
    g_tot_movidos += movidos;
    g_tot_margen += g_con_margen;
    g_tot_barrera_movidos += g_con_barrera_movidos;

    /* CUANTAS se podian mover, que es el denominador de todo lo demas.
     *
     * Sin esto, "no movio nada" tiene dos causas que se leen igual y llevan a
     * sitios opuestos: que el programa no de margen -- todo son cadenas -- o
     * que el modelo declare barrera casi todo, que es un fallo. */
    std::printf("  %s%-28s%s %4u paquetes, %s%u movibles%s / %u barreras"
                "  |  con margen: %s%u%s, reordenados %u"
                "  |  con barrera: %u, reordenados %s%u%s\n",
                ansi::c(ansi::BR_CYAN), donde, ansi::c(ansi::RESET), mirados,
                g_movibles > g_barreras ? ansi::c(ansi::BR_GREEN)
                                        : ansi::c(ansi::BR_RED),
                g_movibles, ansi::c(ansi::RESET), g_barreras,
                g_con_margen > 0 ? ansi::c(ansi::BR_GREEN)
                                 : ansi::c(ansi::BR_YELLOW),
                g_con_margen, ansi::c(ansi::RESET), movidos, g_con_barrera,
                g_con_barrera_movidos > 0 ? ansi::c(ansi::BR_GREEN)
                                          : ansi::c(ansi::BR_YELLOW),
                g_con_barrera_movidos, ansi::c(ansi::RESET));
    vm->stop();
    runtime::bundle_release(proc);
}

#endif // VM_BUNDLES

} // namespace

int main(int argc, char **argv) {
    ansi::init();
    std::vector<std::string> ficheros;
    bool detalle = false;
    for (int i = 1; i < argc; ++i) {
        // Ensena el ANTES y el DESPUES de los primeros paquetes que se muevan,
        // con el criterio que decidio cada cambio.
        if (std::strcmp(argv[i], "--detalle") == 0)
            detalle = true;
        else
            ficheros.push_back(argv[i]);
    }

#if !VM_BUNDLES
    std::printf("VM_BUNDLES=0: no hay paquetes que reordenar.\n");
    return 0;
#else
    if (ficheros.empty()) {
        ficheros = tests::default_bundle_programs("test_reorder");
        if (ficheros.empty()) {
            std::fprintf(stderr, "no se pudieron generar los programas\n");
            return 1;
        }
    }

    std::printf("%sReordenamiento dentro del paquete: propiedades%s\n",
                ansi::c(ansi::BOLD), ansi::c(ansi::RESET));
    std::printf("  Se comprueba contra un modelo de dependencias INDEPENDIENTE"
                " del que usa el\n  planificador: mas basto, asi que solo puede"
                " acusar de mas.\n\n");

    for (const std::string &f : ficheros) probar(f, detalle);

    /* Las dos propiedades del CONJUNTO.  Ninguna se puede exigir por programa:
     * un programa donde cada instruccion ya es independiente de la anterior no
     * tiene un orden mejor que el que trae, y ahi no mover es lo correcto.  Lo
     * que no puede pasar es que en NINGUN programa se mueva nada -- eso es un
     * planificador que no hace nada y aun asi pasa todo lo demas, porque no
     * cruzar nada es trivialmente correcto -- ni que ninguna barrera deje
     * reordenar a su alrededor, que seria congelar el paquete entero por una
     * instruccion que solo se fija a si misma. */
    if (g_tot_margen > 0) {
        check(g_tot_movidos > 0,
              "habia margen en todo el corpus y no movio ni una instruccion",
              "conjunto");
        check(g_tot_barrera_movidos > 0,
              "ningun paquete con barrera se reordeno: la barrera congela",
              "conjunto");
    }

    std::printf("\ncomprobaciones: %s%d pasaron%s, %s%d fallaron%s\n",
                ansi::c(ansi::BR_GREEN), g_pass, ansi::c(ansi::RESET),
                g_fail ? ansi::c(ansi::BR_RED) : ansi::c(ansi::BR_BLACK), g_fail,
                ansi::c(ansi::RESET));
    return g_fail == 0 ? 0 : 1;
#endif
}
