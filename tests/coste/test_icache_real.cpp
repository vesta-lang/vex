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

/**
 * @brief Cuantas veces se ejecuto cada opcode, y cuantas de ellas fallaron.
 *
 * Es la mitad que le faltaba al modelo de coste.  @c test_coste_opcodes da
 * `exec` y `decode` por opcode y por microarquitectura, y dice en su propio
 * JSON que lo que manda es
 *     exec + P_fallo * decode
 * pero que `P_fallo` no cabe ahi porque no es una propiedad del opcode: sale
 * de que PCs conviven en el bucle.  Aqui SI se puede medir, porque estamos
 * ejecutando.
 *
 * Se cuenta por @c InstrFormat -- el descriptor de la instruccion, que es el
 * mismo puntero con el que el test de coste enumera las tablas -- y no por
 * indice de despacho, para que el join no dependa de reproducir la formula
 * `(is_not_extended == 0) ? (0x100 | opcode_index) : is_not_extended`.
 */
struct Opcode {
    const char *nombre = nullptr;
    uint64_t ejecutadas = 0;
    uint64_t fallos = 0; ///< de esas, cuantas hubo que descodificar
};

/**
 * @brief Longitud de los tramos RECTOS de la traza.
 *
 * Un tramo recto es lo que se ejecuta entre dos saltos tomados: la instruccion
 * siguiente esta en `pc + size_instr`.  Se detecta comparando el pc que viene
 * con el que tocaria, asi que NO hace falta saber que opcodes saltan ni como:
 * es exacto y no depende de ningun modelo.
 *
 * Es el dato que decide si una ventana tipo OoO tiene material.  Una ventana
 * de 64 no sirve de nada si el codigo salta cada 4 instrucciones -- da igual
 * lo bien implementada que este, no hay de donde sacar instrucciones
 * independientes.  Y al reves: tramos largos son la condicion NECESARIA (no
 * suficiente: falta que sean independientes) para que reordenar o emitir
 * varias a la vez tenga sentido.
 */
struct Tramos {
    uint64_t cuantos = 0; ///< tramos rectos cerrados
    uint64_t instrs = 0;  ///< instrucciones dentro de tramos
    uint64_t actual = 0;  ///< longitud del tramo en curso
    uint64_t maximo = 0;
    /// Histograma por potencias de dos: [0]=1, [1]=2-3, [2]=4-7, ...
    uint64_t reparto[24] = {};
    /// Instrucciones que caen en tramos de al menos 2^k.  Es lo que se lee
    /// para decir "el X% del tiempo se pasa en tramos de 32 o mas".
    uint64_t instrs_en[24] = {};

    void cerrar() {
        if (actual == 0) return;
        ++cuantos;
        instrs += actual;
        if (actual > maximo) maximo = actual;
        int k = 0;
        while ((1ull << (k + 1)) <= actual && k < 23)
            ++k;
        ++reparto[k];
        for (int i = 0; i <= k; ++i)
            instrs_en[i] += actual;
        actual = 0;
    }
};

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
    /// Histograma por opcode, clavado por el puntero al @c InstrFormat.
    std::unordered_map<const void *, Opcode> por_opcode;
    Tramos tramos;
    /// Cuantas instrucciones descodifica cada funcion de decode.  Dice si un
    /// modelo de dependencias por FORMA de operandos seria aplicable o se
    /// quedaria sin cubrir la mayoria de la traza.
    std::unordered_map<const void *, uint64_t> por_decode;
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
            // El fallo se apunta segun la RAMA que se toma, no segun si
            // `cached` es nulo: la condicion del hot path lleva las dos cosas,
            // y con `decoded_ptr` nulo se descodifica aunque la entrada
            // estuviera.  Mirando solo `cached`, esa vuelta se contaria como
            // acierto en el histograma y como fallo en el total.
            bool fallo = false;
            if (cached != nullptr && proc->decoded_ptr != nullptr) {
                proc->decoded_ptr = cached;
                ++c.aciertos;
            } else {
                fallo = true;
                ++c.fallos;
                // Si ya lo habiamos descodificado, esta vuelta la paga una
                // expulsion: es lo que cuesta de verdad que la icache se pise.
                if (!vistos.insert(pc).second) ++c.redecodes;
                runtime::decode_instruction(proc);
            }
            for (Config &cf : alt)
                cf.acceso(pc);

            // El histograma se cuenta DESPUES de resolver la icache, porque
            // hasta ahi no se sabe si esta instruccion pago descodificacion.
            // El descriptor esta puesto tanto en el acierto (viene en la
            // entrada cacheada) como en el fallo (lo acaba de poner
            // decode_instruction).
            if (proc->decoded_ptr != nullptr &&
                proc->decoded_ptr->metadata != nullptr) {
                Opcode &o =
                    c.por_opcode[(const void *)proc->decoded_ptr->metadata];
                if (o.nombre == nullptr)
                    o.nombre = proc->decoded_ptr->metadata->name;
                ++o.ejecutadas;
                if (fallo) ++o.fallos;
                if (proc->decoded_ptr->metadata->decode != nullptr)
                    ++c.por_decode[(const void *)
                                       proc->decoded_ptr->metadata->decode];
            }

            // Tramo recto: la instruccion siguiente cae justo detras de esta.
            // Se mira DESPUES de ejecutar, comparando el pc que quedo con el
            // que tocaria, asi que vale igual para saltos, llamadas y retornos
            // sin tener que reconocerlos.
            const uint64_t siguiente =
                pc + (proc->decoded_ptr != nullptr
                          ? proc->decoded_ptr->flags_info.size_instr
                          : 0);
            ++c.tramos.actual;

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
            // Si el pc no quedo donde tocaba, hubo transferencia de control y
            // el tramo recto se acaba aqui.
            if (proc->registers.rip.raw() != siguiente) c.tramos.cerrar();
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

    c.tramos.cerrar(); // el que quedaba a medias cuenta igual
    c.distintos = vistos.size();
    c.completo = c.parada_limpia || proc->state == runtime::HALT ||
                 proc->state == runtime::DEAD;
}

/// Un array de contadores como lista JSON.  `instrs_en[k]` son las
/// instrucciones que caen en tramos de al menos 2^k, que es lo que hay que
/// agregar entre programas para decir "el X% del trabajo esta en tramos de 32
/// o mas" sobre un corpus entero.
std::string lista(const uint64_t *v, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        if (i) s += ", ";
        s += std::to_string(v[i]);
    }
    return s;
}

/// De que tabla de descodificacion sale un descriptor, y con que indice.
struct Sitio {
    const char *tabla;
    int indice;
};

/**
 * @brief Localiza un @c InstrFormat en las tablas de descodificacion.
 *
 * La clave del cruce con @c test_coste_opcodes tiene que ser (tabla, indice)
 * y no el nombre: hay descriptores DISTINTOS que se llaman igual -- `mov` sale
 * dos veces en el histograma de cualquier bench -- y unir por nombre sumaria
 * costes de instrucciones que no son la misma.
 *
 * Las dos tablas son arrays de 0x100 en este mismo proceso, asi que el sitio
 * sale de restar punteros.  Es la misma enumeracion que hace el test de coste.
 */
Sitio sitio_de(const void *m) {
    const auto *p = static_cast<const runtime::InstrFormat *>(m);
    if (p >= runtime::decode_table_primary &&
        p < runtime::decode_table_primary + 0x100)
        return {"primary", (int)(p - runtime::decode_table_primary)};
    if (p >= runtime::decode_table_extended &&
        p < runtime::decode_table_extended + 0x100)
        return {"extended", (int)(p - runtime::decode_table_extended)};
    return {"?", -1};
}

/**
 * @brief Vuelca el histograma para cruzarlo con el modelo de coste.
 *
 * A mano y sin dependencias: son cuatro campos y un array, y meter aqui el
 * JSON de nlohmann por esto obligaria a arrastrarlo a un test que hoy no lo
 * necesita.  Los nombres de opcode del proyecto son identificadores, asi que
 * no hay nada que escapar; aun asi se comprueba, porque un JSON roto se
 * descubre tarde y lejos.
 */
void escribir_json(const std::string &ruta,
                   const std::vector<std::pair<std::string, Cuenta>> &benches) {
    FILE *f = std::fopen(ruta.c_str(), "wb");
    if (f == nullptr) {
        std::printf("  no pude escribir %s\n", ruta.c_str());
        return;
    }
    std::fprintf(f, "{\n  \"icache_entradas\": %u,\n  \"icache_vias\": %d,\n",
                 runtime::ICACHE_SIZE, (int)ICACHE_WAYS);
    std::fprintf(f, "  \"benches\": [\n");
    for (size_t i = 0; i < benches.size(); ++i) {
        const Cuenta &c = benches[i].second;
        std::fprintf(
            f,
            "    {\n      \"bench\": \"%s\",\n"
            "      \"instrucciones\": %llu,\n"
            "      \"fallos\": %llu,\n"
            "      \"redecodes\": %llu,\n"
            "      \"pc_distintos\": %llu,\n"
            "      \"completo\": %s,\n"
            "      \"tramos\": {\"cuantos\": %llu, \"instrs\": %llu, "
            "\"maximo\": %llu, \"instrs_en\": [%s]},\n"
            "      \"opcodes\": [\n",
            benches[i].first.c_str(), (unsigned long long)c.pasos,
            (unsigned long long)c.fallos, (unsigned long long)c.redecodes,
            (unsigned long long)c.distintos, c.completo ? "true" : "false",
            (unsigned long long)c.tramos.cuantos,
            (unsigned long long)c.tramos.instrs,
            (unsigned long long)c.tramos.maximo,
            lista(c.tramos.instrs_en, 24).c_str());
        // Ordenados por uso: el que mas se ejecuta es el que mas pesa en la
        // prediccion, y asi el fichero se puede leer sin herramientas.
        std::vector<std::pair<const void *, const Opcode *>> ops;
        ops.reserve(c.por_opcode.size());
        for (const auto &kv : c.por_opcode)
            ops.emplace_back(kv.first, &kv.second);
        std::sort(ops.begin(), ops.end(),
                  [](const std::pair<const void *, const Opcode *> &a,
                     const std::pair<const void *, const Opcode *> &b) {
                      return a.second->ejecutadas > b.second->ejecutadas;
                  });
        for (size_t k = 0; k < ops.size(); ++k) {
            const char *n = ops[k].second->nombre ? ops[k].second->nombre : "?";
            if (std::strchr(n, '"') != nullptr ||
                std::strchr(n, '\\') != nullptr)
                n = "?";
            const Sitio s = sitio_de(ops[k].first);
            std::fprintf(f,
                         "        {\"opcode\": \"%s\", \"tabla\": \"%s\", "
                         "\"indice\": %d, \"ejecutadas\": %llu, "
                         "\"fallos\": %llu}%s\n",
                         n, s.tabla, s.indice,
                         (unsigned long long)ops[k].second->ejecutadas,
                         (unsigned long long)ops[k].second->fallos,
                         k + 1 < ops.size() ? "," : "");
        }
        std::fprintf(f, "      ]\n    }%s\n",
                     i + 1 < benches.size() ? "," : "");
    }
    std::fprintf(f, "  ]\n}\n");
    std::fclose(f);
    std::printf("  JSON: %s\n", ruta.c_str());
}

const char *base(const std::string &ruta) {
    size_t p = ruta.find_last_of("/\\");
    return ruta.c_str() + (p == std::string::npos ? 0 : p + 1);
}

} // namespace

int main(int argc, char **argv) {
    std::vector<std::string> ficheros;
    uint64_t tope = kTopePorDefecto;
    std::string ruta_json;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tope") == 0 && i + 1 < argc)
            tope = std::strtoull(argv[++i], nullptr, 10);
        else if (std::strcmp(argv[i], "--json") == 0 && i + 1 < argc)
            ruta_json = argv[++i];
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
    // Se guarda entera para el JSON: el histograma por opcode es lo que hay
    // que cruzar con `test_coste_opcodes`, y no cabe en la tabla de pantalla.
    std::vector<std::pair<std::string, Cuenta>> por_bench;

    for (const std::string &f : ficheros) {
        runtime::ManageVM manager(nullptr, 0);
        runtime::VM *vm = manager.loader.create_vm_instance(1);
        runtime::ProcessVM *proc = nullptr;
        try {
            proc = manager.loader.load_executable(*vm, f);
        } catch (const std::exception &e) {
            std::printf("%-20s  %s\n", base(f),
                        T("VX9241", {e.what()}).c_str());
            ++fallidos;
            continue;
        }
        if (proc == nullptr) {
            std::printf("%-20s  %s\n", base(f),
                        T("VX9241", {"nullptr"}).c_str());
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
        if (!ruta_json.empty()) por_bench.emplace_back(base(f), c);
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
        std::printf(
            "%-20s %13llu %7.3f%% %12llu %11llu %7s%s\n", base(f),
            (unsigned long long)c.pasos, pct, (unsigned long long)c.redecodes,
            (unsigned long long)c.distintos, cabe.c_str(), nota.c_str());
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
          {N(g_pasos), N(g_fallos), P(gp), N(g_redecodes),
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
            "  %-30s %7u %9.4f%% %14llu %+8.1f%%\n",
            etiqueta(c, i == 0).c_str(),
            (unsigned)(c.entradas * sizeof(runtime::DecodedInstr) / 1024), pf,
            (unsigned long long)c.expulsiones, rel);
    }

    if (fallidos)
        std::printf("\n%s\n", T("VX9240", {N((unsigned)fallidos)}).c_str());

    // --- Tramos rectos ------------------------------------------------------
    // La pregunta que contesta esta tabla: si se metiera una ventana tipo OoO
    // o se emitieran varias instrucciones a la vez, cuanto material habria.
    // Un tramo de 4 no da para nada por bien que se implemente; uno de 64 si.
    if (!por_bench.empty()) {
        std::printf("\nTramos rectos (instrucciones entre saltos tomados)\n");
        std::printf("  %-20s %9s %9s %9s %9s %9s\n", "bench", "tramos", "media",
                    "maximo", ">=8", ">=32");
        std::printf("  %s\n", std::string(72, '-').c_str());
        Tramos g;
        for (const auto &kv : por_bench) {
            const Tramos &t = kv.second.tramos;
            if (t.cuantos == 0) continue;
            g.cuantos += t.cuantos;
            g.instrs += t.instrs;
            if (t.maximo > g.maximo) g.maximo = t.maximo;
            for (int i = 0; i < 24; ++i) {
                g.reparto[i] += t.reparto[i];
                g.instrs_en[i] += t.instrs_en[i];
            }
            std::string n = kv.first;
            if (n.size() > 5 && n.compare(n.size() - 5, 5, ".velb") == 0)
                n.resize(n.size() - 5);
            std::printf("  %-20s %9llu %9.2f %9llu %8.1f%% %8.1f%%\n",
                        n.c_str(), (unsigned long long)t.cuantos,
                        (double)t.instrs / (double)t.cuantos,
                        (unsigned long long)t.maximo,
                        100.0 * (double)t.instrs_en[3] / (double)t.instrs,
                        100.0 * (double)t.instrs_en[5] / (double)t.instrs);
        }
        std::printf("  %s\n", std::string(72, '-').c_str());
        if (g.cuantos) {
            std::printf("  %-20s %9llu %9.2f %9llu %8.1f%% %8.1f%%\n", "TOTAL",
                        (unsigned long long)g.cuantos,
                        (double)g.instrs / (double)g.cuantos,
                        (unsigned long long)g.maximo,
                        100.0 * (double)g.instrs_en[3] / (double)g.instrs,
                        100.0 * (double)g.instrs_en[5] / (double)g.instrs);
            std::printf("\n  reparto de tramos por longitud (tramos, no "
                        "instrucciones):\n   ");
            for (int i = 0; i < 16; ++i) {
                if (g.reparto[i] == 0) continue;
                std::printf(" %d-%d:%.1f%%", 1 << i, (1 << (i + 1)) - 1,
                            100.0 * (double)g.reparto[i] / (double)g.cuantos);
            }
            std::printf("\n");
        }
    }

    // --- Formas de operando -------------------------------------------------
    // Cuanta traza descodifica cada funcion de decode.  Es lo que decide si se
    // puede montar un modelo de dependencias por FORMA (33 funciones) en vez
    // de por opcode (232): si tres formas cubren el 90% de lo ejecutado, el
    // modelo es viable y el resto se trata como barrera.
    if (!por_bench.empty()) {
        std::unordered_map<const void *, uint64_t> formas;
        uint64_t total_f = 0;
        for (const auto &kv : por_bench)
            for (const auto &d : kv.second.por_decode) {
                formas[d.first] += d.second;
                total_f += d.second;
            }
        std::vector<std::pair<uint64_t, const void *>> orden;
        for (const auto &kv : formas)
            orden.emplace_back(kv.second, kv.first);
        std::sort(orden.rbegin(), orden.rend());
        std::printf("\nFormas de operando (por funcion de decode): %zu "
                    "distintas\n",
                    formas.size());
        double acum = 0.0;
        for (size_t i = 0; i < orden.size() && i < 12; ++i) {
            const double pct = 100.0 * (double)orden[i].first / (double)total_f;
            acum += pct;
            // El nombre de la forma no esta en ningun sitio: se identifica por
            // el primer opcode que la usa, que es suficiente para ir a mirarla.
            const char *ejemplo = "?";
            for (const auto &kv : por_bench) {
                for (const auto &o : kv.second.por_opcode) {
                    const auto *m =
                        static_cast<const runtime::InstrFormat *>(o.first);
                    if ((const void *)m->decode == orden[i].second) {
                        ejemplo = o.second.nombre;
                        break;
                    }
                }
                if (std::strcmp(ejemplo, "?") != 0) break;
            }
            std::printf("  %2zu. %-14s %12llu  %6.2f%%  (acumulado %6.2f%%)\n",
                        i + 1, ejemplo, (unsigned long long)orden[i].first, pct,
                        acum);
        }
    }

    if (!ruta_json.empty()) escribir_json(ruta_json, por_bench);
    return 0;
}
