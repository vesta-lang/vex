/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/crash_report.cpp
 * @brief El informe de una caida del proceso: causa, contexto, registros,
 *        desensamblado del sitio y pila con nombres.
 *
 * @par Lo que se puede hacer dentro de un manejador de senal, y lo que no
 * La regla estricta dice que solo valen funciones re-entrantes: ni reservar
 * memoria, ni `printf`.  Un informe que respete eso al pie de la letra no
 * puede decir casi nada, y entonces no sirve para lo unico que existe.
 *
 * Lo que se hace aqui es lo que hacen los informes de caidas de verdad:
 * asumirlo, y protegerse de la unica consecuencia grave -- que el manejador
 * caiga a su vez y el proceso se quede colgado o en un bucle --.  De ahi la
 * bandera de re-entrada: a la segunda caida se sale en el acto, sin escribir
 * nada mas.  Peor que un informe incompleto es un proceso que no termina.
 */

#include "util/crash_report.h"

#include "util/alloc_report.h" // readable_symbol: el nombre de C++ con su firma
#include "util/env_flags.h"    // la caida provocada, para poder comprobarlo

#include <stdexcept>

#include <atomic>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include <capstone/capstone.h>

/* El informe entero sale del catalogo multi-idioma.  Aqui importa mas que en
 * ningun otro sitio: es lo unico que quien se encuentra la caida va a leer, y
 * con frecuencia lo unico que va a poder pegar en un informe.  `diag_lib` es
 * una libreria hoja -- solo la tabla generada --, asi que usarla desde `util`
 * no invierte ninguna dependencia. */
#include "vx/diag/diag_catalog.h"

extern "C" {
#include "util/report/alloc_csv_c.h" // VestaAllocFrame
#include "util/symbols/self_resolver.h"
}

#if defined(_WIN32)
#include <windows.h>
#else
#include <csignal>
#include <dlfcn.h> // de que modulo es una direccion
#include <execinfo.h>
#include <ucontext.h>
#include <unistd.h>
#endif

namespace util {
namespace {

/* Lo que se estaba haciendo.  Punteros pelados y atomicos: el manejador los lee
 * en un contexto donde no se puede reservar ni tomar un cerrojo. */
std::atomic<const char *> g_stage{nullptr};
std::atomic<const char *> g_detail{nullptr};

/* Ya se instalo.  Instalar dos veces encadenaria manejadores y el informe
 * saldria por duplicado. */
std::atomic<bool> g_installed{false};

/* Una caida DENTRO del informe.  A la segunda se corta en seco: un manejador
 * que se cae mientras cuenta una caida deja el proceso sin terminar, que es
 * peor que quedarse sin informe. */
std::atomic<bool> g_reporting{false};

/// @brief Todo sale por el error estandar y se vuelca en el acto.
///
/// Volcar por linea no es exceso de celo: lo que mata el proceso puede ser el
/// sistema (una excepcion en un callback suyo, por ejemplo), y entonces no hay
/// ningun momento posterior en el que vaciar nada.  Lo que quede en el bufer se
/// pierde, y ya se ha visto: cero bytes de salida en una caida real.
void say(const char *fmt, ...) noexcept {
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fflush(stderr);
}

/// @brief Una linea del catalogo, en el idioma activo.
///
/// El codigo y sus argumentos; el texto se escribe AQUI, al imprimir.  Los
/// volcados de registros no pasan por aqui a proposito: `rax`, `rip` y sus
/// valores son datos, no prosa, y traducirlos seria inventar un problema.
void say_code(const char *code,
              const std::vector<std::string> &args = {}) noexcept {
    say("%s\n", vx::diag::format(code, args).c_str());
}

/// @brief Una direccion como texto, para pasarsela al catalogo.
std::string hex_of(const void *p) noexcept {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%016llx",
                  (unsigned long long)(uintptr_t)p);
    return std::string(buf);
}

/**
 * @brief Escribe una direccion con su nombre, y su fichero y linea si se saben.
 *
 * El resolutor devuelve VARIOS marcos para una sola direccion cuando hubo
 * inlining -- la funcion que el compilador metio dentro y la que la contiene --
 * y eso es justo lo que hace falta ver: sin ellos la direccion apunta a una
 * funcion que en el fuente no llama a nada parecido.
 */
std::string say_address(const void *pc, const char *prefix) noexcept {
    std::string first_name;
    VestaAllocFrame frames[8];
    std::memset(frames, 0, sizeof(frames));
    const unsigned n = vesta_self_resolver(pc, frames, 8u);
    if (n == 0) {
        /* Cero es una respuesta legitima: la construccion puede ir despojada.
         * Se dice la direccion igual, que con el mapa del enlazador todavia
         * lleva a algun sitio. */
        say("%s%s  %s\n", prefix, hex_of(pc).c_str(),
            vx::diag::format("crash.no_symbols").c_str());
        return first_name;
    }
    std::string mark;
    for (unsigned i = 0; i < n; ++i) {
        /* El nombre LEGIBLE, no el decorado.  Y ahi van los argumentos: la
         * decoracion de C++ lleva dentro los tipos de la firma, asi que
         * desdecorar no es cosmetica -- es lo que hace que un marco diga con
         * que se llamo la funcion.  Se usa el mismo escritor de nombres que el
         * informe de reservas; tener dos seria tener dos ideas de que es
         * legible, y una envejeceria sin que nadie lo viera. */
        const std::string fn = frames[i].function
                                   ? readable_symbol(frames[i].function)
                                   : std::string("?");
        /* El primero es el marco de verdad; los demas son lo que se metio
         * dentro.  Los argumentos se emparejan contra la firma del PRIMERO,
         * que es el que se llamo. */
        if (first_name.empty()) first_name = fn;
        say("%s%s%s  %s\n", prefix, mark.c_str(), hex_of(pc).c_str(),
            fn.c_str());
        if (frames[i].file != nullptr && frames[i].line != 0)
            say("%s    %s\n", prefix,
                vx::diag::format("crash.at_file",
                                 {frames[i].file,
                                  std::to_string((unsigned)frames[i].line)})
                    .c_str());
        /* Los siguientes son lo que el compilador metio dentro, asi que se
         * marcan como tales en vez de parecer marcos independientes. */
        mark = vx::diag::format("crash.inlined") + " ";
    }
    return first_name;
}

/**
 * @brief El CONTENIDO de la pila en el momento del fallo.
 *
 * La lista de marcos dice por donde se llego; esto dice con QUE.  Ahi estan los
 * argumentos derramados, los temporales y las direcciones de retorno, y en un
 * fallo por puntero suele verse el puntero culpable antes que en ningun otro
 * sitio.
 *
 * Cada palabra que PARECE una direccion se anota con lo que hay en ella.  Sin
 * esa anotacion un volcado de pila es una columna de numeros que nadie lee; con
 * ella, las direcciones de retorno saltan a la vista y la pila se lee como lo
 * que es.  Se descartan los valores pequenos, que son la inmensa mayoria y
 * nunca son direcciones -- el mismo criterio que usa el recolector para
 * decidir que mirar.
 *
 * @param sp     Cima de la pila en el momento del fallo.
 * @param words  Cuantas palabras de 64 bits mostrar.
 */
void say_stack_values(uintptr_t sp, size_t words) noexcept {
    if (sp == 0) return;
    say_code("crash.stack_values");
    const uint64_t *p = reinterpret_cast<const uint64_t *>(sp);
    for (size_t i = 0; i < words; ++i) {
        const uint64_t v = p[i];
        char off[32];
        std::snprintf(off, sizeof(off), "+0x%03llx",
                      (unsigned long long)(i * 8));
        say("    rsp%s  %016llx", off, (unsigned long long)v);
        /* Solo se intenta poner nombre a lo que puede serlo.  Preguntar por
         * cada entero pequeno seria ruido y ademas trabajo por nada. */
        if (v > 0x10000ULL) {
            VestaAllocFrame f[1];
            std::memset(f, 0, sizeof(f));
            if (vesta_self_resolver(reinterpret_cast<const void *>(v), f, 1u) >
                    0 &&
                f[0].function != nullptr)
                say("  <- %s", readable_symbol(f[0].function).c_str());
        }
        say("\n");
    }
}

/**
 * @brief Desensambla alrededor de la instruccion que fallo y la senala.
 *
 * Se lee HACIA ATRAS con cuidado: en x86 no se puede retroceder por el flujo de
 * instrucciones, asi que se empieza unos bytes antes y se descodifica hacia
 * delante hasta caer justo en el PC.  Si no se cae justo, se dice y se
 * desensambla solo desde el PC -- inventar un punto de partida daria un listado
 * verosimil y falso, que es peor que uno corto.
 */
void say_disassembly(uint64_t pc) noexcept {
    if (pc == 0) return;
#if defined(__x86_64__) || defined(_M_X64)
    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return;
#elif defined(__aarch64__) || defined(_M_ARM64)
    csh h;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h) != CS_ERR_OK) return;
#else
    (void)pc;
    return;
#endif

    /* Una ventana corta a los dos lados.  Leer memoria alrededor de un PC que
     * acaba de fallar puede volver a fallar; por eso el manejador de re-entrada
     * de arriba, y por eso no se lee mas de lo justo. */
    constexpr uint64_t kBefore = 48;
    constexpr uint64_t kAfter = 64;
    uint64_t start = (pc > kBefore) ? (pc - kBefore) : pc;

    /* Buscar un punto de partida que ENCAJE con el PC: se prueban los offsets
     * hacia atras y se queda el primero desde el que la descodificacion aterriza
     * exactamente en la instruccion que fallo. */
    bool aligned = (start == pc);
    if (!aligned) {
        for (uint64_t off = kBefore; off > 0 && !aligned; --off) {
            const uint64_t candidate = pc - off;
            uint64_t a = candidate;
            const uint8_t *code = reinterpret_cast<const uint8_t *>(candidate);
            size_t left = static_cast<size_t>(off);
            cs_insn *ins = cs_malloc(h);
            while (left > 0 && a < pc)
                if (!cs_disasm_iter(h, &code, &left, &a, ins)) break;
            cs_free(ins, 1);
            if (a == pc) {
                start = candidate;
                aligned = true;
            }
        }
    }
    if (!aligned) {
        say_code("crash.no_backwards");
        start = pc;
    }

    const size_t total = static_cast<size_t>(pc - start + kAfter);
    const uint8_t *code = reinterpret_cast<const uint8_t *>(start);
    size_t left = total;
    uint64_t addr = start;
    cs_insn *ins = cs_malloc(h);
    while (left > 0 && cs_disasm_iter(h, &code, &left, &addr, ins)) {
        /* La instruccion del fallo se senala.  Sin marca hay que ir contando
         * direcciones a mano, que es justo lo que uno no quiere hacer mirando
         * una caida. */
        const bool here = (ins->address == pc);
        say("  %s 0x%016" PRIx64 "  %-10s %s\n", here ? "=>" : "  ",
            ins->address, ins->mnemonic, ins->op_str);
        if (ins->address > pc + kAfter) break;
    }
    cs_free(ins, 1);
    cs_close(&h);
}

/// @brief La cabecera comun: la causa, la direccion y sobre QUE se estaba.
void say_header(const char *cause_code, const void *fault_addr) noexcept {
    say("\n");
    say_code("crash.header");
    say_code("crash.cause", {vx::diag::format(cause_code)});
    if (fault_addr != nullptr)
        say_code("crash.address", {hex_of(fault_addr)});
    const char *stage = g_stage.load(std::memory_order_relaxed);
    const char *detail = g_detail.load(std::memory_order_relaxed);
    if (stage != nullptr) {
        /* La FASE es un codigo del catalogo, no un texto: asi el informe sale
         * en el idioma de quien lo lee.  El detalle -- una ruta, un nombre de
         * funcion -- va tal cual, porque un nombre propio no se traduce. */
        std::string what = vx::diag::format(stage);
        if (detail != nullptr) {
            what += ' ';
            what += detail;
        }
        say_code("crash.doing", {what});
    } else {
        say_code("crash.doing_unknown");
    }
}

#if defined(_WIN32)

/// @brief Nombre legible de un codigo de excepcion de Windows.
const char *exception_name(DWORD code) noexcept {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION: return "crash.cause.access_violation";
    case EXCEPTION_STACK_OVERFLOW: return "crash.cause.stack_overflow";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "crash.cause.illegal_instruction";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "crash.cause.int_divide_by_zero";
    case EXCEPTION_INT_OVERFLOW: return "crash.cause.int_overflow";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        return "crash.cause.float_divide_by_zero";
    case EXCEPTION_PRIV_INSTRUCTION: return "crash.cause.privileged_instruction";
    case EXCEPTION_IN_PAGE_ERROR: return "crash.cause.in_page_error";
    case EXCEPTION_DATATYPE_MISALIGNMENT: return "crash.cause.misalignment";
    /* Los que no estan en las cabeceras publicas con nombre de excepcion, y que
     * son justo los que mas cuesta reconocer a ojo.  El de corrupcion de monton
     * salio en un caso real y nadie sabia leerlo: se trataba como "excepcion
     * del sistema no reconocida", que manda a buscar al sitio equivocado. */
    case 0xC0000374L: return "crash.cause.heap_corruption";
    case 0xC0000409L: return "crash.cause.stack_buffer_overrun";
    /* Un salto largo NO es un fallo: es la vuelta al punto de rescate.  Sale
     * aqui cuando el manejador del programa Vesta -- que se registra ANTES,
     * porque tiene que poder convertir un fallo en excepcion capturable -- ya
     * ha tratado el fallo original y ha saltado.  Decirlo importa: sin esto el
     * informe acusa a un salto de ser la causa, cuando la causa la conto el
     * otro manejador unas lineas mas arriba. */
    case 0x80000026L: return "crash.cause.longjmp";
    case 0xE06D7363L: return "crash.cause.cpp_uncaught";
    default: return "crash.cause.system";
    }
}

/**
 * @brief TODO lo que trae el registro de la excepcion, no solo su codigo.
 *
 * Las banderas dicen si el fallo es irrecuperable -- con la de no continuable
 * puesta, no hay nada que reintentar -- y los parametros son lo que da sentido
 * al codigo: en un acceso invalido, cual y en que direccion; en otros, lo que
 * el sistema quiera contar.  Sin ellos el codigo solo se puede buscar; con
 * ellos se puede leer.
 *
 * Y se sigue la CADENA: una excepcion puede llevar dentro la que la provoco, y
 * cuando la hay es esa la que explica el fallo -- la de fuera es la
 * consecuencia.
 */
void say_exception_record(const EXCEPTION_RECORD *r, int depth) noexcept {
    if (r == nullptr || depth > 4) return;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "0x%08lX", (unsigned long)r->ExceptionFlags);
    say_code("crash.flags",
             {buf, (r->ExceptionFlags & EXCEPTION_NONCONTINUABLE)
                       ? vx::diag::format("crash.flags.noncontinuable")
                       : vx::diag::format("crash.flags.continuable")});
    if (r->NumberParameters > 0) {
        say_code("crash.params", {std::to_string(r->NumberParameters)});
        const DWORD n = (r->NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS)
                            ? EXCEPTION_MAXIMUM_PARAMETERS
                            : r->NumberParameters;
        for (DWORD i = 0; i < n; ++i) {
            std::snprintf(buf, sizeof(buf), "    [%lu] 0x%016llx",
                          (unsigned long)i,
                          (unsigned long long)r->ExceptionInformation[i]);
            say("%s\n", buf);
        }
    }
    if (r->ExceptionRecord != nullptr) {
        say_code("crash.nested");
        std::snprintf(buf, sizeof(buf), "0x%08lX",
                      (unsigned long)r->ExceptionRecord->ExceptionCode);
        say_code("crash.code", {buf});
        say_exception_record(r->ExceptionRecord, depth + 1);
    }
}

void say_registers(const CONTEXT *c) noexcept {
    if (c == nullptr) return;
    say_code("crash.registers");
#if defined(_M_X64) || defined(__x86_64__)
    say("    rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n",
        (unsigned long long)c->Rax, (unsigned long long)c->Rbx,
        (unsigned long long)c->Rcx, (unsigned long long)c->Rdx);
    say("    rsi=%016llx rdi=%016llx rbp=%016llx rsp=%016llx\n",
        (unsigned long long)c->Rsi, (unsigned long long)c->Rdi,
        (unsigned long long)c->Rbp, (unsigned long long)c->Rsp);
    say("    r8 =%016llx r9 =%016llx r10=%016llx r11=%016llx\n",
        (unsigned long long)c->R8, (unsigned long long)c->R9,
        (unsigned long long)c->R10, (unsigned long long)c->R11);
    say("    r12=%016llx r13=%016llx r14=%016llx r15=%016llx\n",
        (unsigned long long)c->R12, (unsigned long long)c->R13,
        (unsigned long long)c->R14, (unsigned long long)c->R15);
    say("    rip=%016llx eflags=%08lx\n", (unsigned long long)c->Rip,
        (unsigned long)c->EFlags);
    /* Los de segmento tambien.  Casi nunca dicen nada, y el dia que digan algo
     * -- un salto a un selector que no toca, un cambio de modo -- no hay otra
     * forma de verlo.  Caben en una linea. */
    say("    cs=%04x ss=%04x ds=%04x es=%04x fs=%04x gs=%04x\n",
        (unsigned)c->SegCs, (unsigned)c->SegSs, (unsigned)c->SegDs,
        (unsigned)c->SegEs, (unsigned)c->SegFs, (unsigned)c->SegGs);
#endif
}

/**
 * @brief De que modulo es una direccion, y a que distancia de su inicio.
 *
 * Sin esto, una direccion suelta en la pila no dice si es nuestra, del sistema
 * o de una biblioteca de terceros -- que es lo primero que hay que saber para
 * decidir a quien mirar.  Con el desplazamiento desde la base, ademas, sirve
 * aunque el modulo se haya cargado en otra direccion.
 */
void say_module(const void *pc, const char *prefix) noexcept {
    HMODULE mod = nullptr;
    if (!::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              static_cast<LPCSTR>(pc), &mod) ||
        mod == nullptr)
        return;
    char path[MAX_PATH];
    if (::GetModuleFileNameA(mod, path, MAX_PATH) == 0) return;
    /* Solo el nombre del fichero: la ruta entera empuja fuera lo que importa. */
    const char *name = path;
    for (const char *p = path; *p; ++p)
        if (*p == '\\' || *p == '/') name = p + 1;
    const uintptr_t base = reinterpret_cast<uintptr_t>(mod);
    const uintptr_t off = reinterpret_cast<uintptr_t>(pc) - base;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "+0x%llx", (unsigned long long)off);
    say("%s%s\n", prefix,
        vx::diag::format("crash.in_module", {name, buf}).c_str());
}

#endif // _WIN32 -- lo que sigue vale para los dos

/**
 * @brief Los tipos de los parametros de una firma ya legible.
 *
 * Se parte por las comas de PRIMER NIVEL: un `map<int, string>` lleva una coma
 * dentro que no separa parametros, y partir por todas daria tipos partidos por
 * la mitad.  Lo mismo con los parentesis de un puntero a funcion.
 *
 * @param readable Nombre ya desdecorado, con su lista entre parentesis.
 * @return Un tipo por parametro, en orden; vacio si no hay lista o es `()`.
 */
std::vector<std::string> param_types(const std::string &readable) noexcept {
    std::vector<std::string> out;
    /* El parentesis que abre la lista es el que cierra al FINAL del nombre: un
     * `operator()` o un puntero a funcion como parametro traen los suyos por
     * medio, asi que se busca desde atras. */
    size_t close = readable.find_last_of(')');
    if (close == std::string::npos) return out;
    /* Lo que va detras del cierre son calificadores (`const`, `&`), no parte de
     * la lista; el cierre bueno es el ultimo. */
    int depth = 0;
    size_t open = std::string::npos;
    for (size_t i = close + 1; i-- > 0;) {
        const char c = readable[i];
        if (c == ')') ++depth;
        else if (c == '(') {
            if (--depth == 0) {
                open = i;
                break;
            }
        }
    }
    if (open == std::string::npos || close <= open + 1) return out;

    std::string cur;
    int ang = 0, par = 0;
    for (size_t i = open + 1; i < close; ++i) {
        const char c = readable[i];
        if (c == '<') ++ang;
        else if (c == '>') --ang;
        else if (c == '(') ++par;
        else if (c == ')') --par;
        if (c == ',' && ang == 0 && par == 0) {
            out.push_back(cur);
            cur.clear();
            continue;
        }
        if (!cur.empty() || c != ' ') cur.push_back(c);
    }
    if (!cur.empty()) out.push_back(cur);
    if (out.size() == 1 && out[0] == "void") out.clear();
    return out;
}

/**
 * @brief Si un tipo viaja por el banco de coma flotante y no por el general.
 *
 * Importa porque de un `double` no hay nada que ensenar leyendo `rcx`: su valor
 * esta en `xmm0`, y ademas no consume la ranura entera del general.  Decir "no
 * esta aqui" es la respuesta correcta; ensenar el entero que hubiera seria
 * ensenar otra cosa.
 */
bool goes_in_float_bank(const std::string &t) noexcept {
    /* Solo el tipo PELADO: un `double*` es un puntero y viaja por el general. */
    if (t.find('*') != std::string::npos || t.find('&') != std::string::npos)
        return false;
    return t == "float" || t == "double" || t == "long double";
}

#if defined(_WIN32) // se retoma lo que es solo de Windows

/**
 * @brief La lista de argumentos de un marco: cada tipo con su valor.
 *
 * Los tipos salen de la firma -- la decoracion de C++ los lleva dentro -- y los
 * valores de donde la convencion de x86-64 de Windows los pone: los cuatro
 * primeros en `rcx`, `rdx`, `r8` y `r9`, y del quinto en adelante en la pila.
 *
 * DOS avisos que van en el propio texto, porque sin ellos esto enganaria:
 *
 *  - En el marco de MAS ADENTRO los registros llevan todavia los valores; en
 *    los de fuera se leen de la zona de reserva, y ahi estan solo si esa
 *    funcion los guardo.
 *  - Un metodo no estatico se lleva la primera ranura para `this`, y la
 *    decoracion NO distingue un metodo de una funcion libre de un namespace:
 *    `runtime::Scheduler::run_loop` y `runtime::invoke_native_unchecked` se ven
 *    igual.  Asi que el emparejado puede ir corrido UNA posicion en un metodo,
 *    y eso se DICE en vez de presentarlo como seguro.
 */
void say_frame_args(const std::string &readable, const CONTEXT &ctx,
                    bool innermost, const char *prefix) noexcept {
    const std::vector<std::string> types = param_types(readable);
    if (types.empty()) {
        /* Sin firma que emparejar se dan las ranuras a secas, que siguen
         * valiendo: en un marco sin nombre son lo unico que hay. */
        const uint64_t *home = reinterpret_cast<const uint64_t *>(ctx.Rsp + 8);
        say("%s%s\n", prefix,
            vx::diag::format(
                innermost ? "crash.args_regs" : "crash.args_home",
                {hex_of(reinterpret_cast<void *>(
                     innermost ? ctx.Rcx : home[0])),
                 hex_of(reinterpret_cast<void *>(innermost ? ctx.Rdx
                                                           : home[1])),
                 hex_of(reinterpret_cast<void *>(innermost ? ctx.R8 : home[2])),
                 hex_of(reinterpret_cast<void *>(innermost ? ctx.R9
                                                           : home[3]))})
                .c_str());
        return;
    }
    say("%s%s\n", prefix,
        vx::diag::format(innermost ? "crash.args_from_regs"
                                   : "crash.args_from_home")
            .c_str());
    for (size_t i = 0; i < types.size() && i < 16; ++i) {
        std::string value;
        if (goes_in_float_bank(types[i])) {
            value = vx::diag::format("crash.arg_in_float_bank");
        } else if (i < 4) {
            const uint64_t regs[4] = {ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9};
            const uint64_t *home =
                reinterpret_cast<const uint64_t *>(ctx.Rsp + 8);
            const uint64_t v = innermost ? regs[i] : home[i];
            value = hex_of(reinterpret_cast<void *>(v));
        } else {
            /* Del quinto en adelante SIEMPRE en la pila, encima de la zona de
             * reserva.  Ahi no hay ambiguedad: los pone el llamante. */
            const uint64_t *extra =
                reinterpret_cast<const uint64_t *>(ctx.Rsp + 8 + 0x20);
            value = hex_of(reinterpret_cast<void *>(extra[i - 4]));
        }
        say("%s  %s\n", prefix,
            vx::diag::format("crash.arg_line",
                             {std::to_string(i), types[i], value})
                .c_str());
    }
}

/**
 * @brief La pila DEL FALLO, marco a marco, con sus argumentos.
 *
 * Se desenrolla desde el contexto de la excepcion, no se captura la de aqui.
 * Es la diferencia entre ver el camino que llevo al fallo y ver el manejador
 * mirandose a si mismo: capturar la pila actual devolvia `crash_filter`,
 * `UnhandledExceptionFilter` y el despachador del sistema, o sea todo menos lo
 * que hacia falta.
 *
 * Los ARGUMENTOS salen de la zona de reserva que la convencion de x86-64 de
 * Windows obliga a dejar: el llamante reserva 32 bytes encima de la direccion
 * de retorno y el llamado guarda ahi sus cuatro primeros argumentos cuando los
 * necesita en memoria.  Es una LECTURA, no una certeza -- una funcion que no
 * los guarde deja ahi lo que hubiera --, y por eso se dice que son los cuatro
 * primeros y no "los argumentos".  Aun asi, con nombres de funcion al lado,
 * suele bastar para saber con que se la llamo.
 */
void say_stack_walk(const CONTEXT *start) noexcept {
    if (start == nullptr) return;
    say_code("crash.stack");
#if defined(_M_X64) || defined(__x86_64__)
    CONTEXT ctx = *start; // se muta al desenrollar; el original no se toca
    for (int depth = 0; depth < 64 && ctx.Rip != 0; ++depth) {
        const std::string name =
            say_address(reinterpret_cast<const void *>(ctx.Rip), "    ");
        say_module(reinterpret_cast<const void *>(ctx.Rip), "      ");
        if (ctx.Rsp != 0)
            say_frame_args(name, ctx, depth == 0, "      ");

        DWORD64 image_base = 0;
        RUNTIME_FUNCTION *fn =
            ::RtlLookupFunctionEntry(ctx.Rip, &image_base, nullptr);
        if (fn == nullptr) {
            /* Sin tabla de desenrollado -- una hoja, o codigo generado sin
             * describir su marco -- solo queda emular el retorno: la direccion
             * esta en la cima y la pila sube ocho.  Es lo que hace cualquier
             * desenrollador cuando se queda sin datos, y falla igual que ellos
             * si el marco no era el de una llamada. */
            const uint64_t *sp = reinterpret_cast<const uint64_t *>(ctx.Rsp);
            const uint64_t ret = sp ? *sp : 0;
            if (ret == 0) break;
            ctx.Rip = ret;
            ctx.Rsp += 8;
            continue;
        }
        PVOID handler_data = nullptr;
        DWORD64 establisher = 0;
        ::RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx.Rip, fn, &ctx,
                           &handler_data, &establisher, nullptr);
    }
#else
    (void)start;
#endif
}

LONG WINAPI crash_filter(EXCEPTION_POINTERS *info) noexcept {
    if (info == nullptr || info->ExceptionRecord == nullptr)
        return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    /* Lo que NO es una caida se deja pasar: un punto de ruptura es de quien
     * este depurando, y quedarselo seria robarselo. */
    if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    bool expected = false;
    if (!g_reporting.compare_exchange_strong(expected, true))
        return EXCEPTION_CONTINUE_SEARCH; // segunda caida: no insistir

    say_header(exception_name(code),
               (code == EXCEPTION_ACCESS_VIOLATION &&
                info->ExceptionRecord->NumberParameters >= 2)
                   ? reinterpret_cast<const void *>(
                         info->ExceptionRecord->ExceptionInformation[1])
                   : info->ExceptionRecord->ExceptionAddress);
    /* Y el NUMERO, siempre.  Un nombre que no cubra el caso deja al que lo lee
     * sin nada que buscar; el codigo, en cambio, se busca y sale.  Es lo que
     * costo una vuelta entera con el depurador la primera vez. */
    {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%08lX", (unsigned long)code);
        say_code("crash.code", {buf});
    }
    if (code == EXCEPTION_ACCESS_VIOLATION &&
        info->ExceptionRecord->NumberParameters >= 1) {
        const ULONG_PTR what = info->ExceptionRecord->ExceptionInformation[0];
        const char *verb = (what == 0)   ? "crash.access.read"
                           : (what == 1) ? "crash.access.write"
                                         : "crash.access.exec";
        say_code("crash.access", {vx::diag::format(verb)});
    }
    say_exception_record(info->ExceptionRecord, 0);
    say_registers(info->ContextRecord);

    /* El PC sale del CONTEXTO, no del registro de la excepcion.
     *
     * `ExceptionAddress` viene a CERO en algunas excepciones que no las levanta
     * una instruccion concreta -- una corrupcion de monton, por ejemplo, que la
     * detecta el propio monton al revisarse --, y entonces no habia ni sitio ni
     * desensamblado que ensenar.  El `Rip` del contexto es donde estaba el hilo
     * de verdad, y esta siempre. */
    const void *pc = nullptr;
#if defined(_M_X64) || defined(__x86_64__)
    if (info->ContextRecord != nullptr)
        pc = reinterpret_cast<const void *>(info->ContextRecord->Rip);
#elif defined(_M_ARM64) || defined(__aarch64__)
    if (info->ContextRecord != nullptr)
        pc = reinterpret_cast<const void *>(info->ContextRecord->Pc);
#endif
    if (pc == nullptr) pc = info->ExceptionRecord->ExceptionAddress;
    if (pc != nullptr) {
        say_code("crash.where");
        say_address(pc, "    ");
        say_module(pc, "    ");
        say_code("crash.code_around");
        say_disassembly(reinterpret_cast<uint64_t>(pc));
    }

    say_stack_walk(info->ContextRecord);
#if defined(_M_X64) || defined(__x86_64__)
    if (info->ContextRecord != nullptr)
        say_stack_values(static_cast<uintptr_t>(info->ContextRecord->Rsp), 32);
#endif
    say_code("crash.end");
    /* Terminar de verdad, sin el dialogo del sistema ni un volcado que nadie
     * pidio: el informe ya esta dado. */
    return EXCEPTION_EXECUTE_HANDLER;
}

/// @brief Una excepcion de C++ que nadie capturo.
///
/// No la ve el filtro de excepciones del sistema, asi que se cuenta aparte --
/// y es el caso mas probable en un compilador: un `bad_alloc`, un `.at()` fuera
/// de rango, un `throw` de cualquier pase.
void on_terminate() noexcept {
    bool expected = false;
    if (g_reporting.compare_exchange_strong(expected, true)) {
        say_header("crash.cause.cpp_uncaught", nullptr);
        /* El texto de la excepcion, si la hay: es lo mas informativo que se
         * puede dar de un `throw` sin capturar. */
        try {
            if (std::exception_ptr e = std::current_exception()) {
                std::rethrow_exception(e);
            }
        } catch (const std::exception &e) {
            say_code("crash.message", {e.what()});
        } catch (...) {
            say_code("crash.message_foreign");
        }
        void *stack[32];
        const USHORT n = ::CaptureStackBackTrace(0, 32, stack, nullptr);
        if (n > 0) {
            say_code("crash.stack");
            for (USHORT i = 0; i < n; ++i)
                say_address(stack[i], "    ");
        }
        say_code("crash.end");
    }
    std::_Exit(70);
}

#else // POSIX

/**
 * @brief El POR QUE de la senal, que es lo que el numero de senal no dice.
 *
 * `SIGSEGV` a secas solo dice "memoria"; el codigo distingue si la pagina no
 * estaba mapeada -- un puntero a cualquier sitio -- de si estaba pero sin
 * permiso -- escribir en solo lectura --, que llevan a mirar cosas distintas.
 * Igual con `SIGFPE` y `SIGBUS`.
 */
const char *signal_detail(int sig, int code) noexcept {
    switch (sig) {
    case SIGSEGV:
        if (code == SEGV_MAPERR) return "crash.si.segv_maperr";
        if (code == SEGV_ACCERR) return "crash.si.segv_accerr";
        return nullptr;
    case SIGBUS:
        if (code == BUS_ADRALN) return "crash.si.bus_adraln";
        if (code == BUS_ADRERR) return "crash.si.bus_adrerr";
        if (code == BUS_OBJERR) return "crash.si.bus_objerr";
        return nullptr;
    case SIGFPE:
        if (code == FPE_INTDIV) return "crash.si.fpe_intdiv";
        if (code == FPE_INTOVF) return "crash.si.fpe_intovf";
        if (code == FPE_FLTDIV) return "crash.si.fpe_fltdiv";
        if (code == FPE_FLTOVF) return "crash.si.fpe_fltovf";
        if (code == FPE_FLTINV) return "crash.si.fpe_fltinv";
        return nullptr;
    case SIGILL:
        if (code == ILL_ILLOPC) return "crash.si.ill_illopc";
        if (code == ILL_ILLOPN) return "crash.si.ill_illopn";
        if (code == ILL_PRVOPC) return "crash.si.ill_prvopc";
        return nullptr;
    default: return nullptr;
    }
}

/// @copydoc say_module
void say_module(const void *pc, const char *prefix) noexcept {
    Dl_info info;
    if (dladdr(pc, &info) == 0 || info.dli_fname == nullptr) return;
    const char *name = info.dli_fname;
    for (const char *p = info.dli_fname; *p; ++p)
        if (*p == '/') name = p + 1;
    const uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    const uintptr_t off = reinterpret_cast<uintptr_t>(pc) - base;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "+0x%llx", (unsigned long long)off);
    say("%s%s\n", prefix,
        vx::diag::format("crash.in_module", {name, buf}).c_str());
}

/**
 * @brief Los argumentos del marco del fallo, emparejados con su firma.
 *
 * La convencion de SysV pasa los seis primeros enteros o punteros en `rdi`,
 * `rsi`, `rdx`, `rcx`, `r8` y `r9`.  A diferencia de Windows NO hay zona de
 * reserva: el llamante no deja sitio en la pila para ellos, asi que esto solo
 * se puede hacer en el marco DEL FALLO -- que es donde los registros todavia
 * los llevan -- y no en los de mas afuera.  Decirlo es la mitad del trabajo:
 * leerlos de la pila daria numeros verosimiles y falsos.
 */
void say_frame_args_sysv(const std::string &readable, const ucontext_t *uc,
                         const char *prefix) noexcept {
    if (uc == nullptr) return;
#if defined(__x86_64__)
    const greg_t *r = uc->uc_mcontext.gregs;
    const uint64_t regs[6] = {
        static_cast<uint64_t>(r[REG_RDI]), static_cast<uint64_t>(r[REG_RSI]),
        static_cast<uint64_t>(r[REG_RDX]), static_cast<uint64_t>(r[REG_RCX]),
        static_cast<uint64_t>(r[REG_R8]),  static_cast<uint64_t>(r[REG_R9])};
    const std::vector<std::string> types = param_types(readable);
    if (types.empty()) return;
    say("%s%s\n", prefix, vx::diag::format("crash.args_from_regs").c_str());
    for (size_t i = 0; i < types.size() && i < 6; ++i) {
        const std::string value =
            goes_in_float_bank(types[i])
                ? vx::diag::format("crash.arg_in_float_bank")
                : hex_of(reinterpret_cast<void *>(regs[i]));
        say("%s  %s\n", prefix,
            vx::diag::format("crash.arg_line",
                             {std::to_string(i), types[i], value})
                .c_str());
    }
#else
    (void)readable;
    (void)prefix;
#endif
}

const char *signal_name(int sig) noexcept {
    switch (sig) {
    case SIGSEGV: return "crash.cause.access_violation";
    case SIGBUS: return "crash.cause.bus";
    case SIGFPE: return "crash.cause.arithmetic";
    case SIGILL: return "crash.cause.illegal_instruction";
    case SIGABRT: return "crash.cause.aborted";
    default: return "crash.cause.signal";
    }
}

void say_registers(const ucontext_t *uc, uint64_t &pc_out) noexcept {
    pc_out = 0;
    if (uc == nullptr) return;
#if defined(__x86_64__)
    const greg_t *r = uc->uc_mcontext.gregs;
    say_code("crash.registers");
    say("    rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n",
        (unsigned long long)r[REG_RAX], (unsigned long long)r[REG_RBX],
        (unsigned long long)r[REG_RCX], (unsigned long long)r[REG_RDX]);
    say("    rsi=%016llx rdi=%016llx rbp=%016llx rsp=%016llx\n",
        (unsigned long long)r[REG_RSI], (unsigned long long)r[REG_RDI],
        (unsigned long long)r[REG_RBP], (unsigned long long)r[REG_RSP]);
    say("    r8 =%016llx r9 =%016llx r10=%016llx r11=%016llx\n",
        (unsigned long long)r[REG_R8], (unsigned long long)r[REG_R9],
        (unsigned long long)r[REG_R10], (unsigned long long)r[REG_R11]);
    say("    r12=%016llx r13=%016llx r14=%016llx r15=%016llx\n",
        (unsigned long long)r[REG_R12], (unsigned long long)r[REG_R13],
        (unsigned long long)r[REG_R14], (unsigned long long)r[REG_R15]);
    say("    rip=%016llx eflags=%08llx\n", (unsigned long long)r[REG_RIP],
        (unsigned long long)r[REG_EFL]);
    pc_out = static_cast<uint64_t>(r[REG_RIP]);
#elif defined(__aarch64__)
    say_code("crash.registers");
    for (int i = 0; i < 31; i += 4)
        say("    x%-2d=%016llx x%-2d=%016llx x%-2d=%016llx x%-2d=%016llx\n", i,
            (unsigned long long)uc->uc_mcontext.regs[i], i + 1,
            (unsigned long long)uc->uc_mcontext.regs[i + 1], i + 2,
            (unsigned long long)uc->uc_mcontext.regs[i + 2], i + 3,
            (unsigned long long)uc->uc_mcontext.regs[i + 3]);
    say("    sp=%016llx pc=%016llx\n", (unsigned long long)uc->uc_mcontext.sp,
        (unsigned long long)uc->uc_mcontext.pc);
    pc_out = static_cast<uint64_t>(uc->uc_mcontext.pc);
#else
    (void)uc;
#endif
}

void crash_signal(int sig, siginfo_t *si, void *ctx) noexcept {
    bool expected = false;
    if (!g_reporting.compare_exchange_strong(expected, true)) {
        /* Segunda caida, dentro del informe: terminar en seco.  Volver a la
         * accion por defecto seria arriesgarse a un bucle. */
        std::_Exit(70);
    }
    say_header(signal_name(sig), si ? si->si_addr : nullptr);
    if (si != nullptr) {
        /* Toda la ficha de la senal, no solo su numero: el codigo dice POR QUE,
         * y quien la mando importa cuando no viene del procesador. */
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%d", si->si_code);
        const char *detail = signal_detail(sig, si->si_code);
        say_code("crash.si_code",
                 {buf, detail ? vx::diag::format(detail)
                              : vx::diag::format("crash.si.unknown")});
        if (si->si_errno != 0)
            say_code("crash.si_errno", {std::to_string(si->si_errno)});
    }
    uint64_t pc = 0;
    say_registers(static_cast<const ucontext_t *>(ctx), pc);
    std::string fault_fn;
    if (pc != 0) {
        say_code("crash.where");
        fault_fn = say_address(reinterpret_cast<const void *>(pc), "    ");
        say_module(reinterpret_cast<const void *>(pc), "    ");
        say_code("crash.code_around");
        say_disassembly(pc);
    }

    say_code("crash.stack");
    /* El marco del FALLO va primero y sale del contexto, no del recorrido: si
     * la funcion que fallo es una hoja puede no aparecer en el recorrido, y es
     * justo la que interesa. */
    if (pc != 0) {
        const ucontext_t *uc = static_cast<const ucontext_t *>(ctx);
        say_frame_args_sysv(fault_fn, uc, "      ");
    }
    /* Y el resto por el recorrido.  Aqui `backtrace` SI da la pila del fallo y
     * no la del manejador -- el nucleo deja un marco de senal que el
     * desenrollador sabe atravesar --, a diferencia de Windows, donde el filtro
     * corre sobre su propia pila y hay que desenrollar desde el contexto.
     *
     * Se saltan los marcos de este fichero: son el manejador contandose a si
     * mismo. */
    void *stack[64];
    const int n = ::backtrace(stack, 64);
    for (int i = 0; i < n; ++i) {
        if (reinterpret_cast<uint64_t>(stack[i]) == pc) continue;
        const std::string nm = say_address(stack[i], "    ");
        say_module(stack[i], "      ");
        /* SIN argumentos, y se dice por que: la convencion de SysV no obliga a
         * reservar sitio para ellos en la pila del llamante -- no hay zona de
         * reserva como en Windows --, asi que fuera del marco del fallo los
         * registros que los llevaban ya se reusaron.  Inventarlos leyendo la
         * pila daria numeros verosimiles y falsos. */
        (void)nm;
    }
    say_code("crash.args_only_innermost");
    {
        /* La cima de la pila sale del mismo contexto que los registros, que es
         * el del hilo EN EL MOMENTO del fallo -- no la del manejador, que corre
         * en su propia pila. */
        const ucontext_t *uc = static_cast<const ucontext_t *>(ctx);
        uintptr_t sp = 0;
#if defined(__x86_64__)
        if (uc != nullptr)
            sp = static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RSP]);
#elif defined(__aarch64__)
        if (uc != nullptr) sp = static_cast<uintptr_t>(uc->uc_mcontext.sp);
#else
        (void)uc;
#endif
        if (sp != 0) say_stack_values(sp, 32);
    }
    say_code("crash.end");
    std::_Exit(70);
}

void on_terminate() noexcept {
    bool expected = false;
    if (g_reporting.compare_exchange_strong(expected, true)) {
        say_header("crash.cause.cpp_uncaught", nullptr);
        try {
            if (std::exception_ptr e = std::current_exception())
                std::rethrow_exception(e);
        } catch (const std::exception &e) {
            say_code("crash.message", {e.what()});
        } catch (...) {
            say_code("crash.message_foreign");
        }
        void *stack[32];
        const int n = ::backtrace(stack, 32);
        if (n > 0) {
            say_code("crash.stack");
            for (int i = 0; i < n; ++i)
                say_address(stack[i], "    ");
        }
        say_code("crash.end");
    }
    std::_Exit(70);
}

#endif

} // namespace

void crash_report_for(void *platform_exception) noexcept {
#if defined(_WIN32)
    if (platform_exception == nullptr) return;
    /* Se reusa el filtro entero, no una version recortada de el: lo que hay que
     * contar es lo mismo, y dos caminos que informan de una caida acaban
     * contando cosas distintas -- y el que menos se ejecuta es el que se
     * queda corto justo el dia que hace falta --.  El valor que devuelve no
     * significa nada aqui: quien decide que hacer despues es el manejador que
     * llama, que para eso tiene el contexto. */
    (void)crash_filter(static_cast<EXCEPTION_POINTERS *>(platform_exception));
#else
    /* Fuera de Windows el manejador de fallos del procesador YA es el nuestro,
     * asi que no hay ningun otro del que rescatar el suceso.  Se acepta el
     * parametro igual para que quien llame no tenga que envolverlo en
     * condicionales de plataforma. */
    (void)platform_exception;
#endif
}

void install_crash_reporter() noexcept {
    bool expected = false;
    if (!g_installed.compare_exchange_strong(expected, true)) return;
    std::set_terminate(&on_terminate);
#if defined(_WIN32)
    ::SetUnhandledExceptionFilter(&crash_filter);
#else
    /* Pila propia para el manejador.  Sin esto, un desbordamiento de pila --
     * que es una de las caidas que mas interesa contar -- no se puede informar:
     * no queda pila donde ejecutar el manejador. */
    /* Tamano FIJO, no `SIGSTKSZ`.  En la glibc moderna `SIGSTKSZ` dejo de ser
     * una constante -- se resuelve con `sysconf` en ejecucion --, asi que
     * dimensionar con el da un array de tamano variable, que ni es estatico ni
     * lo permite el estandar.  64 KiB sobran para lo que hace el informe y no
     * dependen de la version de la biblioteca. */
    static char alt_stack[64 * 1024];
    stack_t ss{};
    ss.ss_sp = alt_stack;
    ss.ss_size = sizeof(alt_stack);
    ss.ss_flags = 0;
    (void)sigaltstack(&ss, nullptr);

    struct sigaction sa {};
    sa.sa_sigaction = &crash_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    (void)sigaction(SIGSEGV, &sa, nullptr);
    (void)sigaction(SIGBUS, &sa, nullptr);
    (void)sigaction(SIGFPE, &sa, nullptr);
    (void)sigaction(SIGILL, &sa, nullptr);
    (void)sigaction(SIGABRT, &sa, nullptr);
#endif
}

void crash_test_if_asked() noexcept {
    const std::string &kind = util::flag_text(util::FlagId::CrashTest);
    if (kind.empty()) return;
    crash_context_set("crash.stage.crash_test", kind.c_str());
    if (kind == "segv") {
        /* Una lectura por un puntero nulo.  `volatile` para que el optimizador
         * no la borre por ser inutil, que es justo lo que la hace util aqui. */
        volatile const int *p = nullptr;
        (void)*p;
    } else if (kind == "abort") {
        std::abort();
    } else if (kind == "throw") {
        throw std::runtime_error("caida provocada por VESTA_CRASH_TEST=throw");
    } else if (kind == "div0") {
        /* Por variable, no por constante: dividir entre una constante cero no
         * compila, y el optimizador plegaria cualquier cosa que lo parezca. */
        volatile int zero = 0;
        volatile int r = 1 / zero;
        (void)r;
    }
}

void crash_context_set(const char *stage, const char *detail) noexcept {
    g_stage.store(stage, std::memory_order_relaxed);
    g_detail.store(detail, std::memory_order_relaxed);
}

CrashContext::CrashContext(const char *stage, const char *detail) noexcept
    : prev_stage_(g_stage.load(std::memory_order_relaxed)),
      prev_detail_(g_detail.load(std::memory_order_relaxed)) {
    crash_context_set(stage, detail);
}

CrashContext::~CrashContext() noexcept {
    crash_context_set(prev_stage_, prev_detail_);
}

} // namespace util
