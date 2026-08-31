/**
 * @file test_icache_real.cpp
 * @brief Cuenta aciertos y fallos de la icache EJECUTANDO el programa.
 *
 * El otro test (@c test_icache_conflictos) mira el bytecode quieto, adivina
 * donde estan los bucles y cuenta cuantas instrucciones caerian en el mismo
 * conjunto.  Eso es una SIMULACION: dice lo que pasaria si ese bucle se
 * ejecutara, no lo que pasa.  Un bucle que se pisa entero pero se ejecuta dos
 * veces no le importa a nadie, y ahi salia igual de rojo que el bucle caliente.
 *
 * Este carga un @c .velb de verdad, lo ejecuta instruccion a instruccion sobre
 * un @c ProcessVM real y pregunta a la icache REAL -- la misma
 * @c icache_lookup que usa el scheduler, sobre la misma tabla del mismo
 * proceso -- si cada PC estaba o no.  Los numeros que salen son medidos.
 *
 * NO toca la VM.  El bucle de aqui replica el del scheduler
 * (@c NEXT_DISPATCH + el avance de rip de @c run_loop), asi que la secuencia
 * de PCs es la que ejecuta el interprete y la icache se llena igual.  No hay
 * contadores en el hot path ni bandera de compilacion que valga: el binario
 * que se entrega no se entera de que este test existe.
 *
 * De paso, y sobre esa MISMA traza real, se pasan configuraciones
 * alternativas de icache (mas vias, mas entradas, indice con hash) para poder
 * decir si cambiarla compensa, en vez de suponerlo.
 *
 * Uso:
 *   test_icache_real <fichero.velb> [mas.velb ...] [--tope N]
 */

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <unordered_set>
#include <vector>

#include "bytecode/bytecode.h" // Opcodes::HLT
#include "jit/auto_jit.h"      // g_jit_threshold, g_pc_jit_active
#include "runtime/decode_instruction.h"
#include "runtime/exception_runtime.h" // build_stack_trace
#include "runtime/manager_runtime.h"
#include "runtime/proceso_runtime.h"
#include "runtime/vm_registers.h"
#include "vx/diag/diag_catalog.h"

namespace {

/// Atajo al catalogo multi-idioma.  Aqui NO se escribe ni una frase: las
/// palabras salen del catalogo en el idioma activo y los numeros, los codigos
/// y los nombres de fichero viajan como argumentos.
std::string T(const char *codigo, const std::vector<std::string> &args = {}) {
    return vx::diag::format(codigo, args);
}

/// Numero -> texto, para pasarlo como argumento del catalogo.
std::string N(unsigned long long v) {
    return std::to_string(v);
}

/// Numero con decimales -> texto, para los porcentajes.
std::string P(double v, int decimales = 4) {
    char b[32];
    std::snprintf(b, sizeof(b), "%.*f%%", decimales, v);
    return b;
}

/// Tope de instrucciones por programa.  Sin el, un bench largo tarda lo suyo:
/// aqui cada paso paga ademas los contadores y las configuraciones alternas.
constexpr uint64_t kTopePorDefecto = 200ull * 1000 * 1000;

/* -------------------------------------------------------------------------
 * Configuraciones alternativas de icache, alimentadas con la traza REAL.
 *
 * No sustituyen a la medida sobre la icache del proceso: esa es la verdad.
 * Sirven para contestar "y si tuviera mas vias" sin tener que compilar una
 * VM por cada idea.  La traza es real; lo unico modelado es la tabla.
 * ---------------------------------------------------------------------- */
struct Config {
    uint32_t entradas;
    uint32_t vias;
    bool hash; ///< indice = pc ^ (pc >> 10), para romper la periodicidad

    std::vector<uint64_t>
        etiquetas;              ///< pc guardado en cada entrada (0 = vacia)
    std::vector<uint8_t> turno; ///< siguiente via a pisar, por conjunto
    uint64_t aciertos = 0;
    uint64_t fallos = 0;
    uint64_t expulsiones = 0; ///< fallos que pisaron una entrada viva

    void iniciar() {
        etiquetas.assign(entradas, 0);
        turno.assign(entradas / vias, 0);
        aciertos = fallos = expulsiones = 0;
    }

    uint32_t indice(uint64_t pc) const {
        const uint32_t conjuntos = entradas / vias;
        const uint64_t v = hash ? (pc ^ (pc >> 10)) : pc;
        return static_cast<uint32_t>(v & (conjuntos - 1));
    }

    void acceso(uint64_t pc) {
        const uint32_t s = indice(pc);
        uint64_t *base = &etiquetas[static_cast<size_t>(s) * vias];
        for (uint32_t i = 0; i < vias; ++i) {
            if (base[i] == pc) {
                ++aciertos;
                return;
            }
        }
        ++fallos;
        const uint8_t v = turno[s];
        turno[s] = static_cast<uint8_t>((v + 1u) % vias);
        if (base[v] != 0) ++expulsiones;
        base[v] = pc;
    }
};

/// Como se lee esta configuracion en la tabla.  @p actual marca la que lleva
/// la VM hoy, que es la referencia contra la que se comparan las demas.
std::string etiqueta(const Config &c, bool actual) {
    std::string s = c.hash ? T("VX9219", {N(c.entradas), N(c.vias)})
                           : T("VX9218", {N(c.entradas), N(c.vias)});
    if (actual) s += " (" + T("VX9220") + ")";
    return s;
}

struct Cuenta {
    uint64_t pasos = 0;
    uint64_t aciertos = 0;  ///< la icache REAL tenia el PC
    uint64_t fallos = 0;    ///< hubo que descodificar
    uint64_t redecodes = 0; ///< fallo sobre un PC ya descodificado antes
    uint64_t distintos = 0; ///< PCs distintos ejecutados (conjunto de trabajo)
    bool completo = false;  ///< llego a HALT sin tocar el tope
    bool parada_limpia = false; ///< se paro en el `hlt` final del programa
    /// Por que se salio del bucle.  Una corrida que para a las 10
    /// instrucciones sin decir por que es un dato falso con pinta de dato.
    const char *motivo = nullptr;
    bool reventado = false; ///< murio a medias: la cifra de arriba esta corta
};

/**
 * @brief Cuenta lo que se sabe del fallo: donde estaba y como llego.
 *
 * Sin esto, reventar era un codigo 139 y nada mas -- ni que bench, ni en que
 * instruccion, ni con que pila.  Averiguar el motivo costaba ir bajando
 * @c --tope a mano hasta acotar el paso, que es exactamente el trabajo que la
 * traza hace sola.  La pila la arma @c build_stack_trace, la misma que usa la
 * VM cuando un programa se muere de verdad.
 */
std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v);
    return b;
}

/// @copydoc volcar_traza
void volcar_traza(runtime::ProcessVM *proc, const Cuenta &c,
                  const std::string &que) {
    std::printf("\n  !! %s\n", que.c_str());
    std::printf("     %s\n",
                T("VX9227", {N(c.pasos), hex(proc->registers.rip.raw()),
                             N((unsigned)proc->state)})
                    .c_str());
    if (proc->decoded_ptr != nullptr) {
        std::printf("     %s\n",
                    T("VX9228", {hex(proc->decoded_ptr->pc),
                                 N(proc->decoded_ptr->flags_info.opcode_index),
                                 N(proc->decoded_ptr->flags_info.size_instr)})
                        .c_str());
    }
    std::vector<char> buf(16384, '\0');
    const size_t n = runtime::build_stack_trace(proc, buf.data(), buf.size());
    if (n > 0)
        std::printf("     %s\n%s\n", T("VX9229").c_str(), buf.data());
    else
        std::printf("     %s\n", T("VX9230").c_str());
    std::fflush(stdout);
}

/* -------------------------------------------------------------------------
 * Reventones que NO llegan como excepcion.
 *
 * La VM registra su propio manejador (install_host_av_handler) y convierte en
 * FatalError los accesos invalidos que sabe atribuir al bytecode.  Los que no,
 * llegan como SIGSEGV pelado: el proceso se muere, el codigo de salida es 139
 * y no queda ni una linea.  Eso es justo lo que no puede pasar en una
 * herramienta de medida -- un fallo mudo se confunde con "este bench no da
 * datos".  Con esto, cualquier muerte imprime donde estaba y con que pila.
 * ---------------------------------------------------------------------- */
runtime::ProcessVM *g_proc = nullptr;
Cuenta *g_cuenta = nullptr;
const char *g_bench = "?";

extern "C" void al_reventar(int sig) {
    const char *codigo = sig == SIGSEGV   ? "VX9221"
                         : sig == SIGILL  ? "VX9222"
                         : sig == SIGFPE  ? "VX9223"
                         : sig == SIGABRT ? "VX9224"
                                          : "VX9225";
    const std::string nombre = T(codigo);
    std::printf("\n  == %s ==", T("VX9226", {g_bench}).c_str());
    if (g_proc != nullptr && g_cuenta != nullptr) {
        volcar_traza(g_proc, *g_cuenta, nombre);
    } else {
        std::printf("\n  !! %s: %s\n", nombre.c_str(), T("VX9243").c_str());
        std::fflush(stdout);
    }
    // _Exit y no exit: los destructores globales sobre un proceso ya roto
    // vuelven a petar y se llevan por delante lo que acabamos de imprimir.
    std::_Exit(139);
}

void armar_manejadores() {
    std::signal(SIGSEGV, al_reventar);
    std::signal(SIGILL, al_reventar);
    std::signal(SIGFPE, al_reventar);
    std::signal(SIGABRT, al_reventar);
}

/**
 * @brief Ejecuta el proceso paso a paso contando la icache real.
 *
 * Replica el ciclo del scheduler:
 *   1. @c icache_lookup(pc); si falla, @c decode_instruction.
 *   2. ejecutar.
 *   3. avanzar rip con @c size_instr salvo que la instruccion saltara.
 *
 * El paso 1 es literalmente la misma funcion que usa @c NEXT_DISPATCH, sobre
 * el icache de este proceso.  Por eso el acierto/fallo que se cuenta aqui es
 * el que tendria el interprete, no una aproximacion.
 */
void ejecutar(runtime::ProcessVM *proc, Cuenta &c, std::vector<Config> &alt,
              uint64_t tope) {
    std::unordered_set<uint64_t> vistos;
    vistos.reserve(1u << 16);

    try {
        // Las tres condiciones de parada son las del mini run-loop que ya hay
        // en exec_instruction.cpp.  La de err_thread es la que faltaba: cuando
        // una instruccion falla, el estado NO pasa a HALT -- se marca el hilo
        // -- y seguir pisando desde ahi es lo que reventaba los benchmarks
        // cortos.
        while (proc->state != runtime::HALT && proc->state != runtime::DEAD &&
               proc->err_thread == runtime::THREAD_NO_ERROR && c.pasos < tope) {
            const uint64_t pc = proc->registers.rip.raw();

            /* --- la medida --- */
            runtime::DecodedInstr *cached = runtime::icache_lookup(proc, pc);
            if (cached != nullptr && proc->decoded_ptr != nullptr) {
                proc->decoded_ptr = cached;
                ++c.aciertos;
            } else {
                ++c.fallos;
                // Si ya lo habiamos descodificado, esta vuelta la paga una
                // expulsion: es lo que cuesta de verdad que la icache se pise.
                if (!vistos.insert(pc).second) ++c.redecodes;
                runtime::decode_instruction(proc);
            }
            for (Config &cf : alt)
                cf.acceso(pc);

            // `hlt` se cuenta pero NO se ejecuta.  Su manejador vacia los
            // finalizadores del GC y avisa al scheduler, y aqui no hay
            // scheduler corriendo: el proceso se muere en la ultima instruccion
            // del programa, con todo el trabajo ya hecho.  Como medida de la
            // icache da igual -- es una instruccion de 2825033 --, pero
            // ejecutarla costaba el bench entero. Las DOS condiciones: `hlt`
            // son los bytes 00 03, o sea prefijo extendido (is_not_extended ==
            // 0) mas indice 3.  Mirando solo el indice, cualquier instruccion
            // normal cuyo campo valga 3 pasaba por hlt: fib_recursive
            // "terminaba" a las 10 instrucciones.
            if (proc->decoded_ptr != nullptr &&
                proc->decoded_ptr->flags_info.is_not_extended == 0x00 &&
                proc->decoded_ptr->flags_info.opcode_index ==
                    static_cast<uint16_t>(bytecode::Opcodes::HLT)) {
                ++c.pasos;
                c.parada_limpia = true;
                break;
            }

            /* --- ejecutar y avanzar --- */
            // Se llama a execute_instruction y no a exec_cached a mano: ademas
            // de ejecutar, avanza rip igual que el hot path Y para el proceso
            // cuando el opcode no tiene implementacion.  Haciendolo a mano, un
            // programa que termina seguia pisando memoria detras del final: los
            // siete benchmarks mas cortos petaban ahi.
            if (proc->decoded_ptr == nullptr) {
                c.motivo = "VX9239";
                break;
            }
            const runtime::vm_event ev = runtime::execute_instruction(proc);
            ++c.pasos;
            if (ev == runtime::EVT_HALT) {
                c.motivo = "VX9233";
                break;
            }
            if (ev == runtime::EVT_ERROR) {
                c.motivo = "VX9234";
                break;
            }
            if (ev == runtime::EVT_IO_WAIT) {
                // Bloqueo de E/S: fuera del scheduler no hay quien lo
                // despierte.
                c.motivo = "VX9235";
                break;
            }
        }
        if (c.motivo == nullptr) {
            if (c.parada_limpia)
                c.motivo = "VX9236";
            else if (c.pasos >= tope)
                c.motivo = "VX9237";
            else if (proc->state == runtime::HALT ||
                     proc->state == runtime::DEAD)
                c.motivo = "VX9238";
            else if (proc->err_thread != runtime::THREAD_NO_ERROR)
                c.motivo = "VX9232";
        }

    } catch (const std::exception &e) {
        // La VM convierte los accesos invalidos del host en FatalError
        // (install_host_av_handler, que se registra sola al crear la VM), asi
        // que la mayoria de los reventones llegan hasta aqui como excepcion.
        volcar_traza(proc, c, e.what());
        c.reventado = true;
    } catch (...) {
        volcar_traza(proc, c, T("VX9231"));
        c.reventado = true;
    }

    if (proc->err_thread != runtime::THREAD_NO_ERROR) {
        // No es una excepcion: la instruccion fallo y marco el hilo.  Merece
        // la misma traza, que si no el bench sale con una cifra mas baja de la
        // real y nada que explique por que.
        volcar_traza(proc, c, T("VX9232"));
        c.reventado = true;
    }

    c.distintos = vistos.size();
    c.completo = c.parada_limpia || proc->state == runtime::HALT ||
                 proc->state == runtime::DEAD;
}

const char *base(const std::string &ruta) {
    size_t p = ruta.find_last_of("/\\");
    return ruta.c_str() + (p == std::string::npos ? 0 : p + 1);
}

} // namespace

int main(int argc, char **argv) {
    std::vector<std::string> ficheros;
    uint64_t tope = kTopePorDefecto;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tope") == 0 && i + 1 < argc)
            tope = std::strtoull(argv[++i], nullptr, 10);
        else
            ficheros.push_back(argv[i]);
    }
    // El idioma sale del entorno, como en el resto de las herramientas.
    vx::diag::set_language(vx::diag::language_from_env());

    if (ficheros.empty()) {
        std::fprintf(stderr, "%s\n", T("VX9242").c_str());
        return 2;
    }

    // Interprete puro.  La icache es SUYA -- el JIT no la usa --, asi que
    // medirla con el JIT activo no mide nada: `callvm` despacha al codigo
    // compilado y el cuerpo de la funcion no pasa por el interprete.  Asi
    // salia fib_recursive con 10 instrucciones (su main, con la llamada
    // ejecutada en nativo) y la cifra parecia buena.
    jit::g_jit_threshold = UINT32_MAX;
    jit::g_pc_jit_active = false;

    std::printf("%s\n", T("VX9200").c_str());
    std::printf("  %s\n\n",
                T("VX9201", {N(runtime::ICACHE_SIZE), N(ICACHE_WAYS),
                             N(runtime::ICACHE_SETS)})
                    .c_str());
    std::printf("%-20s %13s %8s %12s %11s %7s\n", T("VX9202").c_str(),
                T("VX9203").c_str(), T("VX9204").c_str(), T("VX9205").c_str(),
                T("VX9206").c_str(), T("VX9207").c_str());
    std::printf("%s\n", std::string(76, '-').c_str());
    // Sin esto, un programa que revienta se lleva por delante la cabecera y
    // las filas ya impresas, y no queda ni rastro de por donde iba.
    std::fflush(stdout);

    // Acumulados de las configuraciones alternativas, sobre todos los benches.
    // La PRIMERA es la que lleva la VM hoy: es la referencia de la columna
    // "vs hoy", asi que su sitio no es cosmetico.
    std::vector<Config> total = {
        {runtime::ICACHE_SIZE, ICACHE_WAYS, false, {}, {}, 0, 0, 0},
        {1024, 2, false, {}, {}, 0, 0, 0},
        {1024, 1, true, {}, {}, 0, 0, 0},
        {2048, 1, false, {}, {}, 0, 0, 0},
        {4096, 1, false, {}, {}, 0, 0, 0},
    };
    for (Config &c : total)
        c.iniciar();

    uint64_t g_pasos = 0, g_fallos = 0, g_redecodes = 0;
    int fallidos = 0;

    for (const std::string &f : ficheros) {
        runtime::ManageVM manager(nullptr, 0);
        runtime::VM *vm = manager.loader.create_vm_instance(1);
        runtime::ProcessVM *proc = nullptr;
        try {
            proc = manager.loader.load_executable(*vm, f);
        } catch (const std::exception &e) {
            std::printf("%-20s  %s\n", base(f), T("VX9241", {e.what()}).c_str());
            ++fallidos;
            continue;
        }
        if (proc == nullptr) {
            std::printf("%-20s  %s\n", base(f), T("VX9241", {"nullptr"}).c_str());
            ++fallidos;
            continue;
        }

        std::vector<Config> alt = total;
        for (Config &c : alt)
            c.iniciar();

        // Admitir el proceso en la FSM del scheduler (NEW -> READY) SIN
        // arrancarlo: el bucle lo conduce este test.  Sin esto, `hlt` llamaba
        // a on_event(EVT_HALT) sobre una maquina de estados que nunca habia
        // salido de NEW y se llevaba el proceso por delante -- que es lo que
        // reventaba en los benchmarks que terminan antes del tope.
        vm->make_ready(proc->pid);

        Cuenta c;
        // Para que el manejador de senal sepa de quien hablar si esto se
        // muere a mitad.  Se arma DESPUES de crear la VM: ella instala el
        // suyo al construirse y nos lo pisaria.
        g_proc = proc;
        g_cuenta = &c;
        g_bench = base(f);
        armar_manejadores();
        ejecutar(proc, c, alt, tope);
        g_proc = nullptr;
        g_cuenta = nullptr;

        // Las alternativas se suman al acumulado global.
        for (size_t i = 0; i < total.size(); ++i) {
            total[i].aciertos += alt[i].aciertos;
            total[i].fallos += alt[i].fallos;
            total[i].expulsiones += alt[i].expulsiones;
        }
        g_pasos += c.pasos;
        g_fallos += c.fallos;
        g_redecodes += c.redecodes;

        const double pct =
            c.pasos ? 100.0 * (double)c.fallos / (double)c.pasos : 0.0;
        // "cabe?" = el conjunto de trabajo entra entero en la icache: si cabe
        // y aun asi hay redecodes, es que se pisa (conflicto), no que falte
        // sitio.
        const std::string cabe =
            T(c.distintos <= runtime::ICACHE_SIZE ? "VX9208" : "VX9209");
        const std::string nota = c.reventado  ? "  " + T("VX9210")
                                 : c.completo ? std::string()
                                              : "  " + T("VX9211");
        std::printf("%-20s %13llu %7.3f%% %12llu %11llu %7s%s\n", base(f),
                    (unsigned long long)c.pasos, pct,
                    (unsigned long long)c.redecodes,
                    (unsigned long long)c.distintos, cabe.c_str(),
                    nota.c_str());
        // Una parada que no sea el final del programa se explica siempre: sin
        // esto, un bench que hizo 10 instrucciones sale en la tabla como si
        // fuera una medida buena.
        if (!c.parada_limpia && c.motivo != nullptr)
            std::printf("      %s\n", T("VX9212", {T(c.motivo)}).c_str());
        std::fflush(stdout);
    }

    std::printf("%s\n", std::string(76, '-').c_str());
    const double gp =
        g_pasos ? 100.0 * (double)g_fallos / (double)g_pasos : 0.0;
    std::printf(
        "%s\n",
        T("VX9213",
          {N(g_pasos), N(g_fallos), P(gp),
           N(g_redecodes),
           P(g_pasos ? 100.0 * (double)g_redecodes / (double)g_pasos : 0.0)})
            .c_str());

    std::printf("\n%s\n", T("VX9214").c_str());
    std::printf("  %-30s %7s %10s %14s %9s\n", T("VX9215").c_str(), "KB",
                T("VX9204").c_str(), T("VX9216").c_str(), T("VX9217").c_str());
    const double ref =
        total.empty() || total[0].fallos == 0 ? 0.0 : (double)total[0].fallos;
    for (size_t i = 0; i < total.size(); ++i) {
        const Config &c = total[i];
        const double pf =
            g_pasos ? 100.0 * (double)c.fallos / (double)g_pasos : 0.0;
        const double rel =
            ref > 0 ? 100.0 * ((double)c.fallos - ref) / ref : 0.0;
        std::printf(
            "  %-30s %7u %9.4f%% %14llu %+8.1f%%\n", etiqueta(c, i == 0).c_str(),
            (unsigned)(c.entradas * sizeof(runtime::DecodedInstr) / 1024), pf,
            (unsigned long long)c.expulsiones, rel);
    }

    if (fallidos)
        std::printf("\n%s\n", T("VX9240", {N((unsigned)fallidos)}).c_str());
    return 0;
}
