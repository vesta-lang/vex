/**
 * @file exception_runtime.cpp
 * @brief Implementacion del sistema FatalError
 */

#include "util/env_flags.h"
#include "runtime/exception_runtime.h"

#include "util/thread_slot.h" // ranura por hilo propia (sin la TLS emulada)
#include "vx/module/namespace_flatten.h" // demangle_symbol: el nombre escrito
#include "runtime/decode_instruction.h"
#include "runtime/proceso_runtime.h"
#include "runtime/scheduler.h"
#include "runtime/runtime.h"
#include "loader/loader.h"
#include "loader/class_registry.h"
#include "debug/debugger.h"
#include "disasm/disasm.h"
#include "jit/auto_jit.h"
#include "jit/backend_caps.h" // rasgos del procesador que ejecuta (mismo CPUID
                              // con el que se decide que instrucciones emitir)

#include <capstone/capstone.h>

#include "vx/asm/instr_db.h" // que EXIGE una instruccion, preguntado a la base
#include "vx/diag/diag_catalog.h"
#include "vxdbg/codec.h"
#include "vxdbg/roots.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <memory>

#include <csetjmp>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <mutex>
#include <unordered_map>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <signal.h>
#include <csignal>   // std::signal / std::raise
#include <pthread.h> // limites REALES de la pila del hilo (pthread_getattr_np):
                     // recorrerla mas alla de su final mata el proceso
#include <ucontext.h> // estado de la maquina al fallar (el mismo que Windows
                      // entrega en su CONTEXT): sin el, un fallo se cuenta con
                      // menos detalle en Linux que en Windows
#endif

namespace runtime {

/**
 * @brief Carpeta del grafo de conocimiento del programa.
 *
 * La misma que usa el compilador al emitirlo.  Se repite aqui en vez de
 * incluir el frontend: el runtime no depende de el, y el dia que dejaran de
 * coincidir lo unico que pasaria es que la traza sale mas escueta.
 */
static std::string vxdbg_cache_dir() {
    {
        const std::string &v = util::flag_text(util::FlagId::CacheDir);
        if (!v.empty()) return v + "/vxdbg";
    }
    return ".cache/vxdbg";
}

// ---------------------------------------------------------------------
// Estado global de la clase FatalError
// ---------------------------------------------------------------------

loader::ClassInfo *g_fatal_error_class = nullptr;
static std::once_flag g_fatal_init_flag;

// ---------------------------------------------------------------------
// Tabla de debug por metodo.  Mapea MethodInfo* -> MethodDebug.
// Mutex porque puede llenarse concurrentemente desde varios procesos
// (cada VM ejecuta su __module_init).  Lecturas concurrentes con
// shared_lock no necesarias en MVP -- el lookup es raro (solo en
// build_stack_trace que solo corre tras un crash).
// ---------------------------------------------------------------------

static std::unordered_map<loader::MethodInfo *, MethodDebug> g_method_debug;
static std::mutex g_method_debug_mtx;

void register_method_debug(loader::MethodInfo *method, const char *file,
                           size_t file_len, uint32_t line) {
    if (!method) return;
    std::lock_guard<std::mutex> lk(g_method_debug_mtx);
    MethodDebug md;
    md.source_file.assign(file ? file : "", file ? file_len : 0);
    md.start_line = line;
    g_method_debug[method] = std::move(md);
}

const MethodDebug *lookup_method_debug(loader::MethodInfo *method) {
    if (!method) return nullptr;
    std::lock_guard<std::mutex> lk(g_method_debug_mtx);
    auto it = g_method_debug.find(method);
    if (it == g_method_debug.end()) return nullptr;
    return &it->second;
}

// Offsets de los fields de FatalError dentro del slot de 56 bytes.
// Documentados en exception_runtime.h.  Constantes para que los
// accesos sean directos sin tener que mirar el FieldInfo en cada
// throw (perf-critical path).
constexpr uint32_t FATAL_OFF_KIND = sizeof(loader::ObjectHeader); // 24
constexpr uint32_t FATAL_OFF_PC = FATAL_OFF_KIND + 8;             // 32
constexpr uint32_t FATAL_OFF_MSG_PTR = FATAL_OFF_PC + 8;          // 40
constexpr uint32_t FATAL_OFF_TRACE_PTR = FATAL_OFF_MSG_PTR + 8;   // 48
constexpr uint32_t FATAL_SLOT_SIZE = FATAL_OFF_TRACE_PTR + 8;     // 56

// ---------------------------------------------------------------------
// Init: registra FatalError en el ClassRegistry del Loader publico.
// ---------------------------------------------------------------------

void init_exception_classes(loader::Loader &loader_ref) {
    // Lock once: la primera VM hace el define_class; las siguientes
    // ven g_fatal_error_class ya inicializado y salen sin tocar el
    // registry.  init_once garantiza thread-safety.
    std::call_once(g_fatal_init_flag, [&loader_ref]() {
        auto &reg = loader_ref.class_registry();

        // Si ya existe (e.g. test que reinicia la VM), reutilizamos.
        if (auto *existing = reg.find_class("FatalError")) {
            g_fatal_error_class = existing;
            return;
        }

        // Definicion de los 4 fields fijos.  Todos kind=PRIMITIVE
        // size 8 para que los offsets sean predecibles y sin padding
        // adicional (el ABI documentado en exception_runtime.h asume
        // qword-aligned).
        std::vector<loader::FieldDecl> fields;
        fields.reserve(4);
        {
            loader::FieldDecl f{};
            f.name = "kind";
            f.kind = loader::FIELD_PRIMITIVE;
            f.size_bytes = 8; // se pad a 8 aunque sea i32 logico
            f.access = loader::FIELD_PUBLIC;
            fields.push_back(f);
        }
        {
            loader::FieldDecl f{};
            f.name = "pc";
            f.kind = loader::FIELD_PRIMITIVE;
            f.size_bytes = 8;
            f.access = loader::FIELD_PUBLIC;
            fields.push_back(f);
        }
        {
            loader::FieldDecl f{};
            f.name = "message";
            f.kind = loader::FIELD_PRIMITIVE; // tratado como puntero opaco
            f.size_bytes = 8;
            f.access = loader::FIELD_PUBLIC;
            fields.push_back(f);
        }
        {
            loader::FieldDecl f{};
            f.name = "stack_trace";
            f.kind = loader::FIELD_PRIMITIVE;
            f.size_bytes = 8;
            f.access = loader::FIELD_PUBLIC;
            fields.push_back(f);
        }

        // Sin metodos por ahora (en Vesta se accederan via getfield
        // directo).  Sin super (hereda de Object implicito).
        g_fatal_error_class = reg.define_class("FatalError",
                                               /*super=*/nullptr,
                                               /*interfaces=*/{}, fields,
                                               /*methods=*/{},
                                               /*flags=*/0);

        // BugFix R4: registrar las clases excepcion estandar comunes
        // con solo un field `message` (string ptr).  El lowering del
        // frontend Vesta detecta `new <ExceptionClass>(msg)` y emite la
        // secuencia inline (newobj + store message) sin requerir
        // constructor explicito en bytecode.  El `catch (X e)` accede
        // a `e.message` via getfield offset 24 (justo despues del
        // ObjectHeader).
        const char *std_exc_names[] = {
            "RuntimeException",         "ArithmeticException",
            "IllegalArgumentException", "IndexOutOfBoundsException",
            "NullPointerException",     "IOException",
            "ClassCastException",       "UnsupportedOperationException",
        };
        std::vector<loader::FieldDecl> exc_fields;
        {
            loader::FieldDecl f{};
            f.name = "message";
            f.kind = loader::FIELD_PRIMITIVE;
            f.size_bytes = 8;
            f.access = loader::FIELD_PUBLIC;
            exc_fields.push_back(f);
        }
        for (const char *n : std_exc_names) {
            if (!reg.find_class(n)) {
                (void)reg.define_class(n,
                                       /*super=*/nullptr,
                                       /*interfaces=*/{}, exc_fields,
                                       /*methods=*/{},
                                       /*flags=*/0);
            }
        }
    });
}

// ---------------------------------------------------------------------
// Stack trace builder estilo Java
// ---------------------------------------------------------------------

/**
 * @brief Nombre de la funcion que contiene una direccion de codigo.
 *
 * La cadena de marcos solo conoce METODOS registrados, asi que para todo lo
 * demas -- una funcion libre, o un metodo comptime, que al bajarse se
 * convierte en un simbolo generado sin `MethodInfo` detras -- la traza se
 * quedaba en un `<top>` con una direccion en crudo, que no dice nada.
 *
 * La tabla de simbolos del ejecutable si sabe donde empieza cada funcion, asi
 * que basta con quedarse con la de direccion mas alta que no pase del PC.
 *
 * @param vm     Proceso, para llegar a los ejecutables cargados.
 * @param pc     Direccion a resolver.
 * @param out_off Desplazamiento dentro de la funcion, si se encuentra.
 * @return El nombre, o nullptr si ninguna tabla lo cubre.
 */
/**
 * @brief Pasa un simbolo interno a algo que se pueda leer.
 *
 * La conversion vive junto al aplanado de namespaces, que es quien construye
 * esos nombres: aqui habia una copia, y dos sitios que deshacen lo que un
 * tercero hace acaban conociendo reglas distintas.
 *
 * @param raw Nombre tal como esta en la tabla de simbolos.
 * @return El nombre legible.
 */
static std::string demangle_symbol(const std::string &raw) {
    return vx::demangle_symbol(raw);
}

/**
 * @brief Que declaro un simbolo, segun el grafo de conocimiento del programa.
 *
 * El grafo se localiza por el CONTENIDO del artefacto que se esta ejecutando,
 * no por su nombre: asi un binario que se renombro o se movio sigue
 * explicandose con el suyo y nunca con el de otra compilacion.
 *
 * Se carga una sola vez.  Si no hay nada -- porque el programa se compilo en
 * otra maquina, o porque se borro la cache -- se sigue sin decir nada extra: la
 * traza vale igual, solo que mas escueta.
 *
 * @param vm Proceso que fallo.
 * @param symbol Simbolo ya resuelto.
 * @return Descripcion breve ("metodo de Lector"), o vacio.
 */
static std::string
entity_note_for_symbol(ProcessVM *vm, const std::string &symbol,
                       std::string *out_file = nullptr,
                       vxdbg::ContentHash *out_sum = nullptr,
                       const vxdbg::SpanMap **out_spans = nullptr) {
    struct Grafo {
        bool intentado = false;
        bool hay = false;
        vxdbg::ArtifactMap map;
        vxdbg::SpanMap spans;
        std::unique_ptr<vxdbg::FileNodeStore> store;
    };
    static Grafo g;
    // El grafo se carga una vez y se comparte.  Hace falta candado porque el
    // compilador puede compilar varios modulos a la vez, y un fallo en dos de
    // ellos entraria aqui desde dos hilos: sin el, uno leeria el mapa mientras
    // el otro lo esta construyendo.
    static std::mutex g_mtx;
    std::lock_guard<std::mutex> lk(g_mtx);

    if (!g.intentado) {
        g.intentado = true;
        std::string path;
        for (const auto &exe :
             vm->scheduler.vm_reference.loader_public.executables)
            if (exe && !exe->source_path.empty()) {
                path = exe->source_path;
                break;
            }
        if (!path.empty()) {
            std::ifstream f(path, std::ios::binary);
            if (f) {
                const std::string bytes((std::istreambuf_iterator<char>(f)),
                                        std::istreambuf_iterator<char>());
                if (!bytes.empty()) {
                    const std::string dir = vxdbg_cache_dir();
                    g.store = std::make_unique<vxdbg::FileNodeStore>(dir);
                    const vxdbg::CacheRootRepository repo(dir, *g.store);
                    const vxdbg::BuildId build{
                        vxdbg::hash_bytes(bytes.data(), bytes.size())};
                    g.hay = repo.lookup(build, g.map);
                    // Los tramos son opcionales: si no estan, la traza sale
                    // igual, solo que sin subrayar.
                    repo.lookup_spans(build, g.spans);
                }
            }
        }
    }
    if (out_spans) *out_spans = &g.spans;
    if (!g.hay) return {};

    /* La tabla del ejecutable nombra el codigo `code.<funcion>`; el grafo lo
     * guarda por el nombre de la funcion a secas, que es como lo conoce quien
     * lo genero.  Sin quitar el prefijo no casaba NINGUNO, y el grafo entero --
     * firmas, entidades, de quien deriva -- no llegaba a verse aunque estuviera
     * emitido y publicado. */
    const std::string limpio =
        (symbol.rfind("code.", 0) == 0) ? symbol.substr(5) : symbol;
    const auto id = g.map.find(limpio);
    if (id.hash.empty()) return {};
    vxdbg::LanguageEntity e;
    if (!vxdbg::load_node(*g.store, id.hash, e)) return {};
    // Se dice como lo llama SU lenguaje, no la especie generica: quien lee
    // reconoce "metodo" o "constructor", no "Function".
    std::string nota =
        e.lang_kind.empty() ? std::string("declarado") : e.lang_kind;
    nota += " ";
    // Quien lo declara, para poder decir despues QUE es y DONDE vive.
    vxdbg::LanguageEntity duenyo;
    bool hay_duenyo = false;
    for (const auto &rel : e.relations) {
        if (rel.kind != vxdbg::RelationKind::DeclaredIn) continue;
        hay_duenyo = vxdbg::load_node(*g.store, rel.target.hash, duenyo) &&
                     !duenyo.name.empty();
        break;
    }
    if (hay_duenyo) nota += duenyo.name + ".";
    nota += e.name;
    // Con la firma, porque es lo que distingue un metodo de sus sobrecargas y
    // lo que se parece a lo que hay escrito en el fuente.  El nombre con el que
    // se emitio -- `ctor_1` -- no se parece a nada.
    for (const auto &a : e.attributes)
        if (a.name == "signature") {
            nota += a.text;
            break;
        }
    /* Y de QUE es miembro, con su genero y su fichero.  Que un metodo
     * pertenezca a un `struct` y no a una `class` cambia como se pasa, quien lo
     * posee y donde vive su memoria: al explicar un fallo eso importa tanto
     * como el nombre.  Es justo lo que el grafo sabe y una tabla de simbolos
     * no. */
    /* Una funcion libre no tiene propietario, pero SI tiene fichero.  Sin esto
     * solo se ensenaba el fuente de lo que pertenecia a un tipo, que es la
     * mitad de los sitios donde puede fallar algo. */
    if (!hay_duenyo && out_file && !e.declared_at.file.hash.empty()) {
        vxdbg::FileNode propio;
        if (vxdbg::load_node(*g.store, e.declared_at.file.hash, propio) &&
            !propio.path.empty()) {
            *out_file = propio.path;
            if (out_sum) *out_sum = propio.checksum;
        }
    }
    if (hay_duenyo && !duenyo.lang_kind.empty()) {
        nota += ", de " + duenyo.lang_kind + " " + duenyo.name;
        vxdbg::FileNode f;
        if (!duenyo.declared_at.file.hash.empty() &&
            vxdbg::load_node(*g.store, duenyo.declared_at.file.hash, f) &&
            !f.path.empty()) {
            if (out_file) *out_file = f.path;
            if (out_sum) *out_sum = f.checksum;
            nota += " (" + f.path;
            if (duenyo.declared_at.begin_line > 0)
                nota += ":" + std::to_string(duenyo.declared_at.begin_line);
            nota += ")";
        }
    }
    return nota;
}

/**
 * @brief Codigo de catalogo de un tipo de fallo.
 *
 * El texto NO se escribe aqui: vive en el catalogo, con su codigo estable y en
 * todos los idiomas.  Un fallo en ejecucion es un diagnostico como cualquier
 * otro, y quien lo lee tiene el mismo derecho a leerlo en su idioma que quien
 * lee un error de compilacion.
 *
 * @param kind Tipo de fallo.
 * @return Su codigo.
 */
static const char *fatal_kind_code(uint32_t kind) {
    switch (kind) {
    case FATAL_NULL_POINTER: return "VX7001";
    case FATAL_DIVISION_BY_ZERO: return "VX7002";
    case FATAL_STACK_OVERFLOW: return "VX7003";
    case FATAL_STACK_UNDERFLOW: return "VX7004";
    case FATAL_ILLEGAL_INSTRUCTION: return "VX7005";
    case FATAL_INVALID_SYSCALL: return "VX7006";
    case FATAL_SEGMENTATION_FAULT: return "VX7007";
    case FATAL_NATIVE_CRASH: return "VX7008";
    case FATAL_NATIVE_EXCEPTION: return "VX7009";
    case FATAL_OUT_OF_MEMORY: return "VX7010";
    case FATAL_USER_ABORT: return "VX7011";
    default: return "VX7012";
    }
}

/**
 * @brief Ensena un fallo que nadie capturo.
 *
 * Va a la salida de error y no a la estandar: es un fallo, y quien encadene la
 * salida del programa con otra cosa no debe tragarselo mezclado con los datos.
 *
 * @param vm Proceso que fallo.
 * @param kind Tipo de fallo.
 */
/// Que fallo acabo con el proceso.  0 = ninguno.  Lo lee quien decide con
/// que codigo sale el programa; ponerlo aqui evita que cada sitio que arranca
/// una VM tenga que ir a buscarlo por su cuenta.
static std::atomic<uint32_t> g_last_fatal_kind{0};

int last_fatal_exit_code() {
    switch (g_last_fatal_kind.load(std::memory_order_relaxed)) {
    case 0: return 0;
    /* SIGFPE: operacion aritmetica invalida. */
    case FATAL_DIVISION_BY_ZERO: return 128 + 8;
    /* SIGSEGV: la memoria no era suya.  El desbordamiento de pila entra aqui
     * porque es exactamente eso: pasarse del final. */
    case FATAL_NULL_POINTER:
    case FATAL_SEGMENTATION_FAULT:
    case FATAL_STACK_OVERFLOW:
    case FATAL_STACK_UNDERFLOW:
    case FATAL_NATIVE_CRASH: return 128 + 11;
    /* SIGILL: el codigo no era ejecutable. */
    case FATAL_ILLEGAL_INSTRUCTION: return 128 + 4;
    /* SIGABRT: el programa se rindio -- panic, memoria agotada, una excepcion
     * nativa que nadie recogio. */
    case FATAL_USER_ABORT:
    case FATAL_OUT_OF_MEMORY:
    case FATAL_NATIVE_EXCEPTION: return 128 + 6;
    /* Lo que no encaja en ninguna senal sale con el fallo generico de siempre.
     */
    default: return 1;
    }
}

/**
 * @brief Cuenta un fallo de ejecucion, lo capture alguien o no.
 *
 * Que el programa tenga un `try` alrededor no cambia que el motor acaba de
 * encontrarse con algo que no puede hacer: una division entre cero, una
 * direccion que no es suya, una instruccion que este procesador no tiene.  Eso
 * lo informa quien ejecuta -- interprete o codigo compilado --, no es un
 * mecanismo del lenguaje, y no puede depender de como este escrito el programa:
 * si dependiera, la misma averia seria visible o invisible segun quien la
 * rodease, que es la peor forma de informar.
 *
 * Se cuenta lo MISMO en los dos casos -- codigo del catalogo, mensaje, y la
 * cadena de llamadas con sus tres niveles (fuente, intermedio y maquina) --, y
 * lo unico que se anade cuando hay quien lo recoja es decirlo, para que se lea
 * como lo que es y no como el final del programa.
 *
 * @param vm          Proceso que fallo.
 * @param kind        Tipo de fallo (@c FatalKind).
 * @param hay_handler true si un `catch` del programa va a hacerse cargo.
 */
static void informar_del_fallo(ProcessVM *vm, uint32_t kind, bool hay_handler) {
    /* El codigo de salida solo lo fija el fallo que NADIE recoge: un programa
     * que captura y sigue termina como decida terminar. */
    if (!hay_handler) g_last_fatal_kind.store(kind, std::memory_order_relaxed);
    const char *code = fatal_kind_code(kind);
    const std::string texto = vx::diag::format(code, {});
    std::fprintf(stderr, "\n%s [%s]", texto.c_str(), code);
    if (vm->fatal_msg_buf && vm->fatal_msg_buf[0] != '\0')
        std::fprintf(stderr, ": %s", vm->fatal_msg_buf);
    std::fprintf(stderr, "\n");
    if (hay_handler)
        std::fprintf(stderr, "%s\n", vx::diag::format("VX7024", {}).c_str());
    if (vm->fatal_trace_buf && vm->fatal_trace_buf[0] != '\0')
        std::fprintf(stderr, "%s", vm->fatal_trace_buf);
    std::fflush(stderr);
}

/**
 * @brief El tramo de fuente de una linea dentro de una funcion.
 *
 * Lo produjo quien compilo; aqui solo se consulta.  Vacio = no consta, y
 * entonces no se subraya nada en vez de subrayar a ojo.
 *
 * @param vm Proceso.
 * @param symbol Simbolo de la funcion.
 * @param line Linea.
 * @return El tramo.
 */
static vxdbg::SourceExtent span_for(ProcessVM *vm, const std::string &symbol,
                                    uint32_t line) {
    const vxdbg::SpanMap *sp = nullptr;
    (void)entity_note_for_symbol(vm, symbol, nullptr, nullptr, &sp);
    if (!sp) return {};
    return sp->find((symbol.rfind("code.", 0) == 0) ? symbol.substr(5) : symbol,
                    line);
}

/**
 * @brief Las instrucciones INTERMEDIAS de una posicion del fuente.
 *
 * El `.velb` lleva dentro el intermedio de sus funciones y el cargador ya lo
 * tiene parseado: no hay que ir a buscarlo a ningun sitio ni volver a compilar.
 *
 * Se devuelven solo las de ESA linea y columna -- el fragmento responsable -- y
 * no la funcion entera: en un metodo de verdad son cientos y no dicen nada. Con
 * un tope corto, porque esto acompana a un fallo; quien quiera el volcado tiene
 * una herramienta para eso.
 *
 * @param vm Proceso.
 * @param symbol Simbolo de la funcion tal como aparece en el artefacto.
 * @param line Linea del fuente.
 * @param column Columna, o 0 para no afinar.
 * @return Los nombres de las operaciones, en orden.
 */
/**
 * @brief Un escalon de la cadena de llamadas que el inlinado aplano.
 */
struct EscalonInline {
    std::string funcion; ///< De donde vino el codigo.
    uint32_t linea = 0;  ///< Linea de la llamada, en quien la absorbio.
};

/**
 * @brief Reconstruye las llamadas que se aplanaron en el punto del fallo.
 *
 * Al inlinar, el codigo de otra funcion pasa a vivir aqui conservando las
 * lineas de SU fuente.  La traza entonces atribuye a esta funcion una linea
 * que es de otra -- no es que falten marcos: es que el que sale es falso.  El
 * inlinado dejo constancia de cada llamada que absorbio, y con ella se vuelven
 * a contar.
 *
 * @param vm Proceso.
 * @param symbol Simbolo de la funcion fisica donde ocurrio el fallo.
 * @param line Linea de la instruccion que fallo.
 * @param column Columna, para distinguir dentro de la linea.
 * @return Los escalones de dentro a fuera; vacio si no se inlino nada.
 */
/**
 * @brief Hasta donde llega la pila del hilo actual hacia arriba.
 *
 * Recorrerla mas alla de su final leeria memoria que no es suya.  Se pregunta
 * al sistema cuando sabe decirlo; si no, se acota a un tramo prudente.
 *
 * @param sp Por donde va la pila ahora.
 * @return Direccion tras el ultimo byte que se puede leer.
 */
static uint64_t limite_pila_nativa(uint64_t sp) {
    /// Tramo maximo a recorrer cuando no consta el final real de la pila.
    constexpr uint64_t kTramo = 64u * 1024u;
#if defined(_WIN32)
    ULONG_PTR bajo = 0, alto = 0;
    GetCurrentThreadStackLimits(&bajo, &alto);
    if (alto != 0 && (uint64_t)alto > sp) return (uint64_t)alto;
#elif defined(__linux__)
    /* El final REAL de la pila de este hilo.
     *
     * Solo se preguntaba en Windows; en Linux se daba por bueno el tramo de
     * abajo, que es una SUPOSICION: si al hilo le quedaba menos pila que eso,
     * recorrerla entera se salia a memoria que no es suya y mataba el proceso
     * -- justo mientras se explicaba otro fallo, asi que el programa moria sin
     * llegar a contar el que importaba.  Adivinar hasta donde se puede leer no
     * vale: o lo dice el sistema, o no se recorre. */
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) == 0) {
        void *base = nullptr;
        size_t tam = 0;
        const int ok = pthread_attr_getstack(&attr, &base, &tam);
        pthread_attr_destroy(&attr);
        if (ok == 0 && base != nullptr && tam != 0) {
            const uint64_t alto = (uint64_t)(uintptr_t)base + (uint64_t)tam;
            if (alto > sp) return alto;
        }
    }
    /* Sin respuesta del sistema, no se recorre: mejor una cadena de llamadas
     * corta que llevarse el proceso por delante al construirla. */
    return sp;
#endif
    return sp + kTramo;
}

/**
 * @brief La cadena de llamadas cuando lo que corrio fue codigo NATIVO.
 *
 * Con el codigo compilado los marcos no estan en la pila de la maquina
 * virtual, que es donde mira el barrido normal, sino en la del anfitrion; por
 * eso en JIT solo salia el marco de arriba.  Se recorre esa pila quedandose
 * con los valores que caen DENTRO del codigo de alguna funcion compilada: una
 * direccion de retorno es exactamente eso.
 *
 * Es un barrido conservador, igual que el de la pila de la maquina virtual: un
 * valor que se parezca a una direccion de retorno cuenta como marco.  Puede
 * colar alguno de mas -- restos de marcos ya muertos --, nunca uno falso: la
 * contencion garantiza que la funcion que se nombra es la que contiene esa
 * direccion.
 *
 * @param vm Proceso.
 * @param sp Por donde iba la pila nativa al fallar.
 * @param max Cuantos marcos como mucho.
 * @return Por cada marco, su direccion de retorno NATIVA y la direccion
 *         virtual de la funcion que la contiene, de dentro a fuera.  Hacen
 *         falta las dos: la virtual nombra la funcion, y la nativa es la unica
 *         que permite saber en QUE LINEA estaba -- y con ella, que llamadas se
 *         aplanaron ahi al inlinar.
 */
static std::vector<std::pair<uint64_t, uint64_t>>
cadena_nativa(ProcessVM *vm, uint64_t sp, size_t max) {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    if (sp == 0) return out;
    const uint64_t tope = limite_pila_nativa(sp);
    uint64_t previo = UINT64_MAX;
    for (uint64_t a = (sp + 7u) & ~7ull; a + 8 <= tope && out.size() < max;
         a += 8) {
        uint64_t v = 0;
        std::memcpy(&v, reinterpret_cast<const void *>(a), sizeof(v));
        if (v == 0) continue;
        uint64_t va = 0;
        if (!jit::lookup_vaddr_by_native_pc(v, va)) continue;
        // La misma funcion seguida es la misma llamada, no una nueva.
        if (previo != UINT64_MAX && va == previo) continue;
        previo = va;
        out.emplace_back(v, va);
    }
    (void)vm;
    return out;
}

static std::vector<EscalonInline> inline_chain_at(ProcessVM *vm,
                                                  const std::string &symbol,
                                                  uint32_t line,
                                                  uint32_t column) {
    std::vector<EscalonInline> out;
    if (line == 0) return out;
    const std::string limpio =
        (symbol.rfind("code.", 0) == 0) ? symbol.substr(5) : symbol;
    for (const auto &exe_ptr :
         vm->scheduler.vm_reference.loader_public.executables) {
        if (!exe_ptr) continue;
        for (const auto &fn : exe_ptr->ir_functions) {
            if (fn.name != limpio) continue;
            if (fn.inline_sites.empty()) return out;
            uint32_t sitio = ir::IR_NO_INLINE_SITE;
            for (const auto &bl : fn.blocks) {
                for (const auto &ins : bl.instrs) {
                    if (ins.source_line != line) continue;
                    if (column != 0 && ins.source_column != 0 &&
                        ins.source_column != column)
                        continue;
                    sitio = ins.inline_site;
                    break;
                }
                if (sitio != ir::IR_NO_INLINE_SITE) break;
            }
            /* De dentro a fuera.  Cada escalon dice de que funcion vino el
             * codigo y en que linea de la de fuera se la llamaba; el tope de
             * la cadena es ya la funcion fisica. */
            size_t guarda = 0;
            while (sitio != ir::IR_NO_INLINE_SITE &&
                   sitio < fn.inline_sites.size() &&
                   guarda++ < fn.inline_sites.size()) {
                const ir::InlineSite &s = fn.inline_sites[sitio];
                out.push_back(EscalonInline{s.callee, s.line});
                sitio = s.parent;
            }
            return out;
        }
    }
    return out;
}

static std::vector<std::string> ir_window_at(ProcessVM *vm,
                                             const std::string &symbol,
                                             uint32_t line, uint32_t column,
                                             size_t antes, size_t despues,
                                             const std::string &linea_texto) {
    std::vector<std::string> out;
    if (line == 0) return out;
    const std::string limpio =
        (symbol.rfind("code.", 0) == 0) ? symbol.substr(5) : symbol;
    for (const auto &exe_ptr :
         vm->scheduler.vm_reference.loader_public.executables) {
        if (!exe_ptr) continue;
        for (const auto &fn : exe_ptr->ir_functions) {
            if (fn.name != limpio) continue;
            /* Se aplana la funcion en orden para poder mirar alrededor: el
             * vecindario de una instruccion puede estar en otro bloque. */
            std::vector<const ir::IrInstr *> planas;
            for (const auto &bl : fn.blocks)
                for (const auto &ins : bl.instrs)
                    planas.push_back(&ins);

            size_t culpable = planas.size();
            for (size_t i = 0; i < planas.size(); ++i) {
                if (planas[i]->source_line != line) continue;
                if (column != 0 && planas[i]->source_column != 0 &&
                    planas[i]->source_column != column)
                    continue;
                culpable = i;
                break;
            }
            if (culpable == planas.size()) return out;

            /* De donde sale cada valor: para poder decir "el divisor es
             * this.valor" en vez de "%2".  Un operando es un valor que
             * DEFINIO otra instruccion, y esa instruccion sabe que trozo de
             * fuente la produjo; con el trozo se recorta el texto y el
             * operando tiene nombre.  Solo se mira dentro de la misma linea,
             * que es la que se tiene delante. */
            std::unordered_map<ir::IrValueId, std::string> nombre_de;
            if (!linea_texto.empty()) {
                for (const ir::IrInstr *p : planas) {
                    if (p->dst == ir::IR_NO_VALUE) continue;
                    if (p->source_line != line) continue;
                    if (p->source_column == 0 || p->source_len == 0) continue;
                    const size_t c = p->source_column - 1;
                    if (c >= linea_texto.size()) continue;
                    const size_t n =
                        std::min<size_t>(p->source_len, linea_texto.size() - c);
                    std::string txt = linea_texto.substr(c, n);
                    // Sin espacios en los bordes: el trozo puede traerlos y
                    // como nombre estorban.
                    while (!txt.empty() &&
                           (txt.back() == ' ' || txt.back() == 9))
                        txt.pop_back();
                    if (txt.empty()) continue;
                    nombre_de[p->dst] = std::move(txt);
                }
            }

            const size_t desde = (culpable > antes) ? (culpable - antes) : 0;
            const size_t hasta =
                std::min(planas.size(), culpable + despues + 1);
            for (size_t i = desde; i < hasta; ++i) {
                /* La instruccion ENTERA -- destino, operandos, tipos --
                 * con el MISMO formateador que el volcado del intermedio.  El
                 * nombre de la operacion a secas no dice nada: `load` no
                 * distingue de donde carga ni a donde va. */
                std::ostringstream os;
                ir::print_instr(os, fn, *planas[i]);
                std::string cuerpo = os.str();
                while (!cuerpo.empty() &&
                       (cuerpo.back() == 10 || cuerpo.back() == 13))
                    cuerpo.pop_back();
                // El formateador ya sangra; se le quita para poner la marca.
                const size_t ini_txt = cuerpo.find_first_not_of(' ');
                if (ini_txt != std::string::npos)
                    cuerpo = cuerpo.substr(ini_txt);

                std::string t = (i == culpable) ? "> " : "  ";
                t += cuerpo;
                if (planas[i]->source_line > 0) {
                    t += "   (linea " + std::to_string(planas[i]->source_line);
                    if (planas[i]->source_column > 0)
                        t += ":" + std::to_string(planas[i]->source_column);
                    t += ")";
                }
                /* Y en la culpable, de donde sale cada operando.  Es lo que
                 * convierte "%1 entre %2" en algo que se puede leer. */
                if (i == culpable) {
                    std::string ops;
                    /* El destino tambien: la maquina es de dos direcciones, de
                     * modo que su PRIMER registro es el del destino y no el
                     * del primer operando.  Sin decirlo, quien lee empareja
                     * mal las dos vistas. */
                    std::vector<ir::IrValueId> vals;
                    if (planas[i]->dst != ir::IR_NO_VALUE)
                        vals.push_back(planas[i]->dst);
                    for (ir::IrValueId v : planas[i]->operands)
                        vals.push_back(v);
                    for (ir::IrValueId v : vals) {
                        auto it = nombre_de.find(v);
                        /* En que registro vive, que es lo que une el
                         * intermedio con la instruccion de la maquina: sin
                         * esto se ve `%8` por un lado y `r1=0x2a` por otro sin
                         * que nada diga que son lo mismo. */
                        const uint8_t rg = (v < fn.values.size())
                                               ? fn.values[v].reg
                                               : ir::IR_NO_REG;
                        if (it == nombre_de.end() && rg == ir::IR_NO_REG)
                            continue;
                        if (!ops.empty()) ops += ", ";
                        ops += "%" + std::to_string(v);
                        if (rg != ir::IR_NO_REG)
                            ops += "=r" + std::to_string((unsigned)rg);
                        if (it != nombre_de.end())
                            ops += " (" + it->second + ")";
                    }
                    if (!ops.empty()) t += "   [" + ops + "]";
                }
                out.push_back(std::move(t));
            }
            return out;
        }
    }
    return out;
}

/**
 * @brief Una VENTANA del codigo maquina alrededor de donde fallo.
 *
 * Las instrucciones son de tamano variable, asi que no se puede retroceder
 * desde el fallo: hay que descodificar hacia adelante desde el principio de la
 * funcion, que es la unica frontera conocida, quedandose con las ultimas.
 *
 * @param vm Proceso.
 * @param inicio Direccion donde empieza la funcion.
 * @param pc_fallo Direccion de la instruccion que fallo.
 * @param antes Cuantas ensenar antes.
 * @param despues Cuantas despues.
 * @return Las lineas de texto, con la culpable marcada.
 */
/**
 * @brief Una VENTANA del codigo NATIVO alrededor de donde fallo.
 *
 * Cuando lo que corrio fue codigo compilado, las instrucciones de la maquina
 * virtual NO son las que se ejecutaron: ensenarlas seria dar por ejecutado algo
 * que no lo fue.  Lo que se ejecuto esta en la pagina nativa, y para leerlo hay
 * que desensamblarla.
 *
 * Se descodifica desde el principio de la funcion -- las instrucciones son de
 * tamano variable y no se puede retroceder -- y se recorta alrededor de la que
 * fallo.
 *
 * @param pc_fallo Direccion nativa del fallo.
 * @param antes Cuantas ensenar antes.
 * @param despues Cuantas despues.
 * @return Las lineas de texto, con la culpable marcada.
 */
/**
 * @brief Indice del banco (orden x86-64) de un registro de Capstone.
 *
 * Capstone nombra tambien las mitades (`eax`, `r11d`, `al`): todas viven en el
 * mismo registro de 64 bits, que es el que se guardo.
 *
 * @param r Identificador de Capstone.
 * @return 0..15, o -1 si no es un registro general.
 */
static int indice_de_reg_x86(unsigned r) {
    switch (r) {
    case X86_REG_RAX:
    case X86_REG_EAX:
    case X86_REG_AX:
    case X86_REG_AL: return 0;
    case X86_REG_RCX:
    case X86_REG_ECX:
    case X86_REG_CX:
    case X86_REG_CL: return 1;
    case X86_REG_RDX:
    case X86_REG_EDX:
    case X86_REG_DX:
    case X86_REG_DL: return 2;
    case X86_REG_RBX:
    case X86_REG_EBX:
    case X86_REG_BX:
    case X86_REG_BL: return 3;
    case X86_REG_RSP:
    case X86_REG_ESP: return 4;
    case X86_REG_RBP:
    case X86_REG_EBP: return 5;
    case X86_REG_RSI:
    case X86_REG_ESI:
    case X86_REG_SI: return 6;
    case X86_REG_RDI:
    case X86_REG_EDI:
    case X86_REG_DI: return 7;
    case X86_REG_R8:
    case X86_REG_R8D: return 8;
    case X86_REG_R9:
    case X86_REG_R9D: return 9;
    case X86_REG_R10:
    case X86_REG_R10D: return 10;
    case X86_REG_R11:
    case X86_REG_R11D: return 11;
    case X86_REG_R12:
    case X86_REG_R12D: return 12;
    case X86_REG_R13:
    case X86_REG_R13D: return 13;
    case X86_REG_R14:
    case X86_REG_R14D: return 14;
    case X86_REG_R15:
    case X86_REG_R15D: return 15;
    default: return -1;
    }
}

/**
 * @brief Mnemonico de la instruccion nativa que hay en una direccion.
 *
 * Cuando el procesador rechaza una instruccion, lo unico que se sabe es donde
 * esta.  Desensamblando ESA -- no una ventana, ni el bloque entero -- se
 * obtiene su nombre, que es lo que permite preguntarle a la base de
 * instrucciones que rasgo exige.  Vale igual si el codigo lo genero el
 * compilador en caliente o si vive en un modulo nativo: en los dos casos la
 * direccion es del proceso anfitrion.
 *
 * @param pc Direccion de la instruccion.
 * @return Mnemonico en minusculas, o cadena vacia si no se pudo descodificar.
 */
static std::string mnemonico_nativo_en(uint64_t pc) {
    if (pc == 0) return std::string();
    /* Cuanto se puede leer sin salir de la pagina de la instruccion.
     *
     * 16 bytes es lo maximo que ocupa una instruccion x86, pero pedirlos
     * SIEMPRE es leer memoria que quiza no esta mapeada: si la instruccion cae
     * cerca del final de su pagina, la lectura se va a la siguiente y provoca
     * un segundo fallo -- dentro de la recuperacion del primero, que es el peor
     * momento posible.  Eso hacia que contar el fallo funcionara o matara el
     * programa en silencio segun donde hubiera caido el codigo, o sea de forma
     * distinta en cada ejecucion.
     *
     * Una instruccion puede cruzar la frontera de pagina; en ese caso se
     * descodifica lo que hay hasta el corte y, si no basta, no se dice el
     * mnemonico.  Callar es correcto; leer de mas, no. */
    const uint64_t kPagina = 4096;
    const size_t hasta_fin_de_pagina =
        static_cast<size_t>(kPagina - (pc % kPagina));
    const size_t leer = hasta_fin_de_pagina < 16 ? hasta_fin_de_pagina : 16;
    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return std::string();
    cs_insn *ins = nullptr;
    const size_t n =
        cs_disasm(h, reinterpret_cast<const uint8_t *>(pc), leer, pc, 1, &ins);
    std::string m;
    if (n > 0) {
        m = ins[0].mnemonic;
        cs_free(ins, n);
    }
    cs_close(&h);
    return m;
}

/**
 * @brief Rasgos que declara el procesador que esta ejecutando, en una linea.
 *
 * Es el MISMO CPUID con el que se decide que instrucciones emitir, asi que
 * cuando una instruccion falla por falta de rasgo, esta lista es exactamente el
 * criterio con el que se tomo la decision -- no una aproximacion.
 *
 * @return "SSE2, AVX, AVX2, ERMS" o similar; vacia si no se pudo consultar.
 */
static std::string rasgos_del_procesador() {
    // Los nombres son los de la base de instrucciones (`isa_set` sin el ancho),
    // para que se lean contra lo que exige la instruccion sin traducir nada.
    static const struct {
        uint64_t bit;
        const char *nombre;
    } kTabla[] = {
        {jit::CF_SSE2, "SSE2"},     {jit::CF_SSE42, "SSE42"},
        {jit::CF_POPCNT, "POPCNT"}, {jit::CF_AVX, "AVX"},
        {jit::CF_AVX2, "AVX2"},     {jit::CF_BMI1, "BMI1"},
        {jit::CF_BMI2, "BMI2"},     {jit::CF_AVX512F, "AVX512F"},
        {jit::CF_ERMS, "ERMS"},     {jit::CF_FMA, "FMA"},
        {jit::CF_LZCNT, "LZCNT"},   {jit::CF_F16C, "F16C"},
        {jit::CF_SHA, "SHA"},       {jit::CF_AES, "AES"},
    };
    const uint64_t bits = jit::backend_caps_host_bits();
    std::string out;
    for (const auto &e : kTabla) {
        if ((bits & e.bit) == 0) continue;
        if (!out.empty()) out += ", ";
        out += e.nombre;
    }
    return out;
}

static std::vector<std::string> native_window(ProcessVM *vm, uint64_t pc_fallo,
                                              size_t antes, size_t despues) {
    std::vector<std::string> out;
    uint64_t inicio = 0, tam = 0;
    if (!jit::lookup_region_by_native_pc(pc_fallo, inicio, tam)) return out;

    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return out;
    // Con detalle: hace falta para saber que registros LEE la que fallo y
    // poder decir cuanto valian.
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *ins = nullptr;
    const size_t n = cs_disasm(h, reinterpret_cast<const uint8_t *>(inicio),
                               (size_t)tam, inicio, 0, &ins);
    if (n == 0) {
        cs_close(&h);
        return out;
    }
    /* La que CONTIENE la direccion, no la que empieza justo ahi: cuando lo
     * guardado es un retorno se pregunta por un byte de en medio. */
    size_t culpable = n;
    for (size_t i = 0; i < n; ++i) {
        if (ins[i].address > pc_fallo) break;
        culpable = i;
    }
    if (culpable < n && pc_fallo >= ins[culpable].address + ins[culpable].size)
        culpable = n;
    if (culpable == n) {
        cs_free(ins, n);
        cs_close(&h);
        return out;
    }
    const size_t desde = (culpable > antes) ? (culpable - antes) : 0;
    const size_t hasta = std::min(n, culpable + despues + 1);
    char buf[192];
    for (size_t i = desde; i < hasta; ++i) {
        // Relativo al principio de la funcion: la direccion absoluta cambia en
        // cada ejecucion y no dice nada.
        std::string vals;
        /* De la que fallo, QUE VALIAN los registros que lee.  Solo de esa: los
         * de las de al lado ya han cambiado o aun no se han calculado. */
        if (i == culpable && vm->pending_fault_native_regs_ok &&
            ins[i].detail) {
            cs_regs leidos, escritos;
            uint8_t n_l = 0, n_e = 0;
            if (cs_regs_access(h, &ins[i], leidos, &n_l, escritos, &n_e) == 0) {
                for (uint8_t k = 0; k < n_l; ++k) {
                    const int idx = indice_de_reg_x86(leidos[k]);
                    if (idx < 0) continue;
                    char vb[48];
                    std::snprintf(
                        vb, sizeof(vb), "%s%s=0x%llx", vals.empty() ? "" : " ",
                        cs_reg_name(h, leidos[k]),
                        (unsigned long long)vm->pending_fault_native_regs[idx]);
                    vals += vb;
                }
            }
        }
        if (vals.empty()) {
            std::snprintf(buf, sizeof(buf), "%s +0x%llx  %-8s %s",
                          (i == culpable) ? ">" : " ",
                          (unsigned long long)(ins[i].address - inicio),
                          ins[i].mnemonic, ins[i].op_str);
        } else {
            std::snprintf(buf, sizeof(buf), "%s +0x%llx  %-8s %-24s%s",
                          (i == culpable) ? ">" : " ",
                          (unsigned long long)(ins[i].address - inicio),
                          ins[i].mnemonic, ins[i].op_str, vals.c_str());
        }
        out.push_back(buf);
    }
    cs_free(ins, n);
    cs_close(&h);
    return out;
}

static std::vector<std::string> bytecode_window(ProcessVM *vm, uint64_t inicio,
                                                uint64_t pc_fallo, size_t antes,
                                                size_t despues) {
    std::vector<std::string> out;
    if (inicio > pc_fallo) return out;

    /* Se desensambla con el DESENSAMBLADOR del proyecto, no con un formateo
     * propio.  Ya sabe escribir los operandos de cada instruccion, que es lo
     * que un renderizado por modo de direccionamiento no puede saber: en la
     * tabla extendida cada una coloca sus campos a su manera.  Ademas, si
     * manana cambia una instruccion, cambia en un solo sitio. */
    const uint64_t tope = pc_fallo + 64;
    const size_t largo = (size_t)(tope - inicio);
    if (largo == 0 || largo > 8192) return out;
    std::vector<uint8_t> bytes(largo, 0);
    vm->vm_mem.read_bytes(inicio, bytes.data(), largo);

    disasm::DisasmOptions opts;
    opts.show_hex = true;
    opts.use_color = false;
    opts.stop_at_hlt = false;
    opts.max_bytes = largo;
    const std::vector<disasm::DisasmResult> instrs =
        disasm::disasm_bytes(bytes.data(), largo, inicio, opts);

    size_t culpable = instrs.size();
    for (size_t i = 0; i < instrs.size(); ++i)
        if (instrs[i].address == pc_fallo) {
            culpable = i;
            break;
        }
    if (culpable == instrs.size()) return out;

    const size_t desde = (culpable > antes) ? (culpable - antes) : 0;
    const size_t hasta = std::min(instrs.size(), culpable + despues + 1);
    for (size_t i = desde; i < hasta; ++i) {
        const disasm::DisasmResult &d = instrs[i];
        char buf[256];
        if (i == culpable) {
            /* De la que fallo se ensena tambien QUE VALIAN sus registros.  Es
             * la diferencia entre saber que revento un `div` y saber que
             * revento porque el divisor valia cero.  Solo de esa: los valores
             * de las de al lado ya han cambiado o aun no se han calculado, y
             * ensenarlos seria mentir. */
            DecodedInstr dec{};
            std::string vals;
            if (decode_peek(vm, d.address, dec)) {
                const uint8_t r1 = dec.data_instruction.reg_data.reg1 & 0xF;
                const uint8_t r2 = dec.data_instruction.reg_data.reg2 & 0xF;
                char vb[80];
                std::snprintf(
                    vb, sizeof(vb), "  r%u=0x%llx r%u=0x%llx", (unsigned)r1,
                    (unsigned long long)vm->registers.regs[r1].qword(),
                    (unsigned)r2,
                    (unsigned long long)vm->registers.regs[r2].qword());
                vals = vb;
            }
            std::snprintf(buf, sizeof(buf), "> 0x%llx  %-34s %-8s %-16s%s",
                          (unsigned long long)d.address, d.hex.c_str(),
                          d.mnemonic.c_str(), d.operands.c_str(), vals.c_str());
        } else {
            std::snprintf(buf, sizeof(buf), "  0x%llx  %-34s %-8s %s",
                          (unsigned long long)d.address, d.hex.c_str(),
                          d.mnemonic.c_str(), d.operands.c_str());
        }
        out.push_back(buf);
    }
    return out;
}

static const std::string *symbol_for_pc(ProcessVM *vm, uint64_t pc,
                                        uint64_t &out_off) {
    const std::string *best = nullptr;
    uint64_t best_addr = 0;
    for (const auto &exe_ptr :
         vm->scheduler.vm_reference.loader_public.executables) {
        if (!exe_ptr) continue;
        for (const auto &kv : exe_ptr->symbol_table) {
            if (kv.second <= pc && kv.second >= best_addr) {
                best_addr = kv.second;
                best = &kv.first;
            }
        }
    }
    /* La tabla trae tanto la funcion como sus bloques internos, y el bloque
     * suele ganar por estar mas cerca del PC.  Pero `..._entry_0` o
     * `..._assert_fail_58` son detalles de como se genero el codigo, no algo
     * que quien programa reconozca; si existe un simbolo que es PREFIJO del
     * encontrado, ese es la funcion y es el que hay que ensenar. */
    if (best) {
        const std::string *fn = best;
        for (const auto &exe_ptr :
             vm->scheduler.vm_reference.loader_public.executables) {
            if (!exe_ptr) continue;
            for (const auto &kv : exe_ptr->symbol_table) {
                if (kv.first.size() < fn->size() &&
                    best->rfind(kv.first, 0) == 0) {
                    fn = &kv.first;
                }
            }
        }
        out_off = pc - best_addr;
        return fn;
    }
    return best;
}

size_t build_stack_trace(ProcessVM *vm, char *out, size_t out_size) {
    if (!out || out_size < 2) return 0;
    size_t pos = 0;
    auto append = [&](const char *s, size_t n) {
        const size_t avail = (out_size - 1) - pos;
        const size_t cp = (n < avail) ? n : avail;
        std::memcpy(out + pos, s, cp);
        pos += cp;
    };
    auto append_str = [&](const char *s) {
        if (!s) return;
        append(s, std::strlen(s));
    };
    auto append_hex = [&](uint64_t v) {
        char buf[20];
        int n =
            std::snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
        if (n > 0) append(buf, (size_t)n);
    };
    auto append_dec = [&](uint64_t v) {
        char buf[24];
        int n = std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
        if (n > 0) append(buf, (size_t)n);
    };

    /* Cuando lo que fallo fue una instruccion que este procesador no tiene, se
     * dice QUE instruccion y QUE rasgo exige, antes de la cadena de llamadas.
     * Todo eso ya se sabe y estaba sin juntar: la direccion la da el sistema,
     * el mnemonico el desensamblador, el rasgo la base de instrucciones y lo
     * que la maquina declara, el CPUID que ya se consulta para decidir que
     * emitir. Decir solo "instruccion invalida" era tirar cuatro datos que
     * estaban a mano y dejar a quien lee adivinando cual de las variantes
     * reviento. */
    if (vm->pending_av_kind == 3 && vm->pending_fault_native_pc != 0) {
        const std::string mnem =
            mnemonico_nativo_en(vm->pending_fault_native_pc -
                                (vm->pending_fault_native_is_return ? 1u : 0u));
        if (!mnem.empty()) {
            const std::string exige = vx::instr_db::requisito_de_mnemonico(
                vx::instr_db::Isa::X86, mnem);
            append_str("  ");
            append_str(vx::diag::format("VX7021", {mnem}).c_str());
            append_str("\n");
            if (!exige.empty()) {
                append_str("  ");
                append_str(vx::diag::format("VX7022", {exige}).c_str());
                append_str("\n");
            }
            const std::string tiene = rasgos_del_procesador();
            if (!tiene.empty()) {
                append_str("  ");
                append_str(vx::diag::format("VX7023", {tiene}).c_str());
                append_str("\n");
            }
            append_str("\n");
        }
    }

    // Cabecera con info del proceso y PC actual.
    append_str("Stack trace (Vesta):\n");

    // Frame 0: el PC actual (donde ocurrio el error).  Si hay
    // method en frame_stack lo usamos; si no, solo PC.
    loader::FrameHeader *fr = vm->frame_stack;
    /* Donde estaba el programa al fallar.
     *
     * En codigo compilado no vale el PC de la maquina virtual: ahi no se va
     * actualizando -- ese es el punto de compilar --, de modo que conserva el
     * de la ultima vez que se sincronizo y la traza acababa senalando la
     * primera funcion en vez de la que revento.  Lo que si vale es la
     * direccion NATIVA del fallo, que lleva a la funcion que la contiene y de
     * ahi a su direccion en la maquina virtual. */
    uint64_t cur_pc = vm->registers.rip.raw();
    /// Linea que dice el propio codigo nativo, cuando el fallo fue ahi.  0 =
    /// se sigue el camino normal (la tabla del bytecode).
    uint32_t linea_forzada = 0;
    bool desde_compilado = false;
    /* Si lo guardado es una direccion de RETORNO, se retrocede uno para caer
     * DENTRO de la instruccion que interviene: la llamada, no lo que va
     * despues.  Es lo que hace cualquier desenrollador, y sin ello se marca la
     * siguiente y quien lee no reconoce su propio codigo. */
    const uint64_t nat_pc =
        vm->pending_fault_native_pc -
        (vm->pending_fault_native_is_return && vm->pending_fault_native_pc != 0
             ? 1u
             : 0u);
    if (vm->pending_fault_native_pc != 0) {
        uint64_t va = 0;
        if (jit::lookup_vaddr_by_native_pc(nat_pc, va)) {
            cur_pc = va;
            desde_compilado = true;
            /* Es el PRINCIPIO de la funcion, no la instruccion exacta: no hay
             * que mirar el byte anterior como con un PC que ya avanzo. */
            vm->fatal_pc_exact = true;
            // Y la linea, que dentro de la funcion solo la sabe el propio
            // codigo nativo.
            (void)jit::lookup_line_by_native_pc(nat_pc, linea_forzada);
        }
    }

    // Helper: append "(file.vx:line)" usando primero DebugInfo del
    // .velb cargado (precision pc_offset -> line); fallback a
    // MethodDebug (start_line del metodo).  Item 4: ahora el stack
    // trace muestra la linea EXACTA de la instruccion fallida en
    // lugar de la linea del inicio del metodo.
    /* Posicion en el fuente para un simbolo resuelto por direccion.
     *
     * La seccion de depuracion guarda UN solo fichero por unidad ensamblada,
     * asi que para el codigo que viene de otro modulo el nombre de fichero que
     * hay registrado es el del modulo raiz -- la LINEA es correcta, el fichero
     * no.  Ensenar un fichero equivocado es peor que no ensenarlo: manda a
     * mirar donde no es.  Cuando el simbolo lleva modulo en el nombre (que ya
     * dice donde vive) se muestra solo la linea; si es del propio fichero, se
     * muestran los dos. */
    /* Cuanto retroceder para preguntar por la instruccion que interesa.
     *
     * Una direccion de RETORNO apunta justo despues de la llamada, y el PC de
     * un fallo normal ya avanzo: en los dos hay que mirar el byte anterior.
     * Pero cuando el fallo lo captura el sistema a mitad de instruccion -- un
     * acceso invalido -- el PC apunta a la que fallo, y restar uno se sale a la
     * instruccion de antes: si la que fallo era la PRIMERA de una funcion, la
     * de antes es de OTRA, y la traza acaba enseñando la linea de otro sitio.
     * Que fue exactamente lo que pasaba. */
    const uint64_t atras_top = vm->fatal_pc_exact ? 0u : 1u;

    /* La linea de fuente de un PC.  Misma correccion de `atras` que
     * append_pos: el PC de un fallo ya avanzo y el de un marco es una
     * direccion de retorno. */
    auto linea_de_pc = [&](uint64_t pc, uint64_t atras) -> uint32_t {
        /* Si el fallo fue en codigo compilado, la linea la dice el propio
         * codigo nativo y no la tabla del bytecode: alli el PC de la maquina
         * virtual no se va actualizando, y preguntar por el devuelve la linea
         * de otra sentencia. */
        if (linea_forzada != 0 && pc == cur_pc) return linea_forzada;
        for (const auto &exe_ptr :
             vm->scheduler.vm_reference.loader_public.executables) {
            if (!exe_ptr || !exe_ptr->debug_info) continue;
            auto info = exe_ptr->debug_info->lookup_line(
                static_cast<uint32_t>(pc > atras ? pc - atras : 0));
            if (info.found && info.line > 0) return info.line;
        }
        return 0;
    };

    auto append_pos = [&](uint64_t pc, bool tiene_modulo, uint64_t atras = 1) {
        for (const auto &exe_ptr :
             vm->scheduler.vm_reference.loader_public.executables) {
            if (!exe_ptr || !exe_ptr->debug_info) continue;
            auto info =
                /* Se pregunta por el byte ANTERIOR, no por el PC.  El PC
                 * de un fallo apunta ya a la instruccion siguiente, y el de un
                 * marco de la cadena es una direccion de RETORNO -- justo
                 * despues de la llamada.  Preguntando por el PC tal cual la
                 * respuesta es la sentencia de al lado: una division de la
                 * linea 8 salia como linea 9.  Restar uno cae dentro de la
                 * instruccion que interesa; es lo que hace cualquier
                 * desenrollador. */
                exe_ptr->debug_info->lookup_line(
                    static_cast<uint32_t>(pc > atras ? pc - atras : 0));
            /* Si el fallo fue en codigo compilado, manda la linea que dice el
             * propio codigo nativo: el PC de la maquina virtual no vale ahi. */
            const uint32_t forzada =
                (linea_forzada != 0 && pc == cur_pc) ? linea_forzada : 0;
            if (forzada != 0 || (info.found && info.line > 0)) {
                append_str(" (");
                if (!tiene_modulo && info.file && info.file[0] != '\0') {
                    append_str(info.file);
                    append_str(":");
                } else {
                    append_str("linea ");
                }
                append_dec((uint64_t)(forzada != 0 ? forzada : info.line));
                append_str(")");
                return;
            }
        }
    };

    /* La linea del FUENTE, debajo del marco.  Un numero de linea obliga a abrir
     * el fichero para entender el fallo; el texto lo cuenta solo.  No hace
     * falta nada nuevo: el fichero lo dice el grafo (cada entidad lleva el
     * suyo, sin la mentira de la seccion de depuracion cross-module) y la linea
     * ya se resolvia.  Si el fuente no esta o ya no coincide, simplemente no se
     * ensena. */
    /* Un rotulo con su raya para separar las tres vistas del mismo fallo.
     * Puestas una detras de otra sin nada en medio se leen como un bloque
     * unico y cuesta ver donde acaba el fuente y empieza lo que se ejecuto.
     *
     * El rotulo sale del catalogo -- es texto que lee una persona --, y la
     * raya se escribe con los BYTES de su caracter para que el fuente siga
     * siendo ASCII. */
    static const char kSaltoLinea[] = {(char)10, 0};
    auto append_titulo = [&](const char *codigo) {
        const std::string t = vx::diag::format(codigo, {});
        append_str("      ");
        append(t.c_str(), t.size());
        append_str(" ");
        // U+2500 (raya horizontal).  Se escriben sus BYTES en UTF-8, no el
        // caracter, para que este fuente siga siendo ASCII.
        static const char kRaya[] = {(char)0xE2, (char)0x94, (char)0x80, 0};
        const size_t ancho = (t.size() < 40) ? (40 - t.size()) : 4;
        for (size_t i = 0; i < ancho; ++i)
            append_str(kRaya);
        append_str(kSaltoLinea);
    };

    auto append_source = [&](uint64_t pc, const std::string &archivo,
                             vxdbg::ContentHash resumen,
                             const std::string &simbolo, uint64_t atras = 1,
                             const std::string *simbolo_ir = nullptr) {
        /* El tramo de fuente lo guarda la funcion en la que se ESCRIBIO el
         * codigo, pero el intermedio vive en la que lo ABSORBIO al inlinar.
         * Cuando no coinciden hay que preguntar a cada una por lo suyo. */
        const std::string &sim_ir = simbolo_ir ? *simbolo_ir : simbolo;
        if (archivo.empty()) return;
        uint32_t linea = 0;
        uint32_t col_pc = 0;
        for (const auto &exe_ptr :
             vm->scheduler.vm_reference.loader_public.executables) {
            if (!exe_ptr || !exe_ptr->debug_info) continue;
            auto info =
                /* Se pregunta por el byte ANTERIOR, no por el PC.  El PC
                 * de un fallo apunta ya a la instruccion siguiente, y el de un
                 * marco de la cadena es una direccion de RETORNO -- justo
                 * despues de la llamada.  Preguntando por el PC tal cual la
                 * respuesta es la sentencia de al lado: una division de la
                 * linea 8 salia como linea 9.  Restar uno cae dentro de la
                 * instruccion que interesa; es lo que hace cualquier
                 * desenrollador. */
                exe_ptr->debug_info->lookup_line(
                    static_cast<uint32_t>(pc > atras ? pc - atras : 0));
            if (info.found && info.line > 0) {
                linea = info.line;
                col_pc = info.column;
                break;
            }
        }
        /* En codigo compilado manda la linea que dice el propio codigo nativo.
         * La COLUMNA no la sabe -- el codigo nativo se correlaciona por lineas
         * --, asi que se deja sin fijar y se subraya la sentencia entera. */
        if (linea_forzada != 0 && pc == cur_pc) {
            linea = linea_forzada;
            col_pc = 0;
        }
        if (linea == 0) return;
        std::ifstream f(archivo, std::ios::binary);
        if (!f) return;
        const std::string todo((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
        if (todo.empty()) return;
        /* Si el fichero ya no es el que se compilo, se DICE.  Ensenar una linea
         * de un fuente que cambio despues manda a mirar donde no toca, y
         * callarse deja a quien lee pensando que no habia nada.  Las dos cosas
         * son peores que decirlo. */
        if (!resumen.empty() &&
            vxdbg::hash_bytes(todo.data(), todo.size()) != resumen) {
            const std::string aviso = vx::diag::format("VX7014", {});
            append_str("      ");
            append(aviso.c_str(), aviso.size());
            append_str("\n");
            return;
        }
        std::istringstream fuente(todo);
        std::string texto;
        for (uint32_t i = 0; i < linea && std::getline(fuente, texto); ++i) {
        }
        // Sin la sangria de la izquierda: aqui estorba y descoloca la traza.
        const size_t ini = texto.find_first_not_of(" \t");
        if (ini == std::string::npos) return;
        const std::string limpio = texto.substr(ini);
        append_titulo("VX7016");
        append_str("      ");
        append(limpio.c_str(), limpio.size());
        append_str("\n");

        /* Y el subrayado del tramo exacto, si consta.  Con la linea sola no se
         * distingue cual de las tres llamadas que caben en ella fallo; el tramo
         * lo dice.  Se descuenta la sangria que se quito arriba para que el
         * subrayado caiga donde debe. */
        /* La columna la trae el propio PC: es la de la instruccion que fallo,
         * no la de la primera sentencia de la linea.  Con ella se subraya lo
         * que se estaba evaluando aunque en la linea haya varias cosas. */
        vxdbg::SourceExtent ext = span_for(vm, simbolo, linea);
        if (col_pc > 0) ext.column = col_pc;
        if (ext.length == 0 || ext.column == 0) return;
        if (ext.column - 1 < ini) return; // el tramo empieza en otra linea
        const size_t col = ext.column - 1 - ini;
        if (col >= limpio.size()) return;
        const size_t largo = std::min<size_t>(ext.length, limpio.size() - col);
        append_str("      ");
        for (size_t i = 0; i < col; ++i)
            append_str(" ");
        for (size_t i = 0; i < largo; ++i)
            append_str("^");
        append_str("\n");

        /* Y el INTERMEDIO de ese mismo tramo.  Entre el fuente y la instruccion
         * de la maquina hay un paso que a veces es el que explica el fallo: lo
         * que se pidio, en que se tradujo, y con que acabo.  Se ensena solo si
         * consta; si el intermedio no viaja en el artefacto, no se dice nada.
         */
        const std::vector<std::string> ops =
            ir_window_at(vm, sim_ir, linea, ext.column, 3, 4, texto);
        if (ops.empty()) return;
        append_titulo("VX7017");
        for (const std::string &t : ops) {
            append_str("      ");
            append(t.c_str(), t.size());
            append_str("\n");
        }
    };

    auto append_dbg = [&](loader::MethodInfo *m, uint64_t pc,
                          const char *pc_label) {
        // Buscar DebugInfo precise via los Executables cargados.
        // Accedemos via scheduler.vm_reference.loader_public (la VM
        // propietaria es el owner del Loader publico).
        for (const auto &exe_ptr :
             vm->scheduler.vm_reference.loader_public.executables) {
            if (!exe_ptr || !exe_ptr->debug_info) continue;
            // pc absoluto -> bytecode_offset relativo al inicio del
            // code section del executable.  Asumimos un solo executable
            // (caso comun); para multi-velb el primero que matchee.
            auto info =
                /* Se pregunta por el byte ANTERIOR, no por el PC.  El PC
                 * de un fallo apunta ya a la instruccion siguiente, y el de un
                 * marco de la cadena es una direccion de RETORNO -- justo
                 * despues de la llamada.  Preguntando por el PC tal cual la
                 * respuesta es la sentencia de al lado: una division de la
                 * linea 8 salia como linea 9.  Restar uno cae dentro de la
                 * instruccion que interesa; es lo que hace cualquier
                 * desenrollador. */
                exe_ptr->debug_info->lookup_line(
                    static_cast<uint32_t>(pc ? pc - 1 : 0));
            if (info.found && info.line > 0) {
                append_str(" (");
                if (info.file && info.file[0] != '\0') {
                    append_str(info.file);
                } else if (m) {
                    const MethodDebug *md = lookup_method_debug(m);
                    if (md)
                        append(md->source_file.data(), md->source_file.size());
                    else
                        append_str("?");
                } else {
                    append_str("?");
                }
                append_str(":");
                append_dec((uint64_t)info.line);
                append_str(")");
                return;
            }
        }
        // Fallback: MethodDebug con start_line.
        const MethodDebug *md = m ? lookup_method_debug(m) : nullptr;
        if (md && !md->source_file.empty()) {
            append_str(" (");
            append(md->source_file.data(), md->source_file.size());
            append_str(":");
            append_dec((uint64_t)md->start_line);
            append_str(")");
        } else {
            append_str(" (");
            append_str(pc_label);
            append_str("=");
            append_hex(pc);
            append_str(")");
        }
    };

    /// Ultimo simbolo contado, para que el origen no lo repita.
    const std::string *prev_origen = nullptr;

    // Primer frame: usar metodo del top de la pila si existe.
    append_str("  at ");
    /* El nombre del marco de arriba sale del PC, no del metodo del marco.  El
     * marco solo conoce METODOS registrados, y el codigo que falla a menudo no
     * lo es -- una funcion libre, o un metodo de struct, que al bajarse se
     * vuelven un simbolo suelto.  Cuando eso pasa, `fr->method` sigue apuntando
     * al metodo de QUIEN LLAMO, con lo que se ensenaba un nombre que no
     * corresponde a la linea de al lado. */
    uint64_t off_top = 0;
    const std::string *sym_top = symbol_for_pc(vm, cur_pc, off_top);
    if (sym_top == nullptr && fr && fr->method) {
        const auto &mname = fr->method->name;
        if (mname.data && mname.size > 0) {
            append((const char *)mname.data, mname.size);
        } else {
            append_str("<unknown>");
        }
        // Clase del metodo (owner_class o owner_class si esta).
        if (fr->method->owner_class) {
            const auto &cname = fr->method->owner_class->name;
            if (cname.data && cname.size > 0) {
                append_str(" [");
                append((const char *)cname.data, cname.size);
                append_str("]");
            }
        }
        append_dbg(fr->method, cur_pc, "pc");
        append_str("\n");
    } else {
        if (const std::string *sym = sym_top) {
            /* Si esta linea no es de esta funcion -- vino de otra al inlinar
             * --, se dice de quien es.  Poner el nombre de la funcion fisica
             * junto a una linea ajena no es perder informacion: es dar una
             * falsa. */
            const std::vector<EscalonInline> aplanado =
                inline_chain_at(vm, *sym, linea_de_pc(cur_pc, atras_top), 0);
            const std::string legible =
                aplanado.empty() ? demangle_symbol(*sym)
                                 : demangle_symbol(aplanado.front().funcion);
            append(legible.c_str(), legible.size());
            if (!aplanado.empty()) {
                append_str(" [aplanado en ");
                const std::string fis = demangle_symbol(*sym);
                append(fis.c_str(), fis.size());
                append_str("]");
            }
            // Que ES lo que fallo, no solo como se llama: si el grafo lo sabe,
            // se dice ("constructor de Lector") en vez de dejar un nombre
            // suelto que quien lee tiene que ir a buscar al fuente.
            std::string archivo_top;
            vxdbg::ContentHash resumen_top;
            // La nota describe a QUIEN pertenece la linea, que si hubo
            // inlinado no es la funcion fisica.
            const std::string nota = entity_note_for_symbol(
                vm, aplanado.empty() ? *sym : aplanado.front().funcion,
                &archivo_top, &resumen_top);
            if (!nota.empty()) {
                append_str(" [");
                append(nota.c_str(), nota.size());
                append_str("]");
            }
            append_pos(cur_pc, legible.find('.') != std::string::npos,
                       atras_top);
            append_str("\n");
            /* El tramo de fuente es de quien escribio la linea; el intermedio,
             * de quien acabo conteniendola tras el inlinado. */
            append_source(cur_pc, archivo_top, resumen_top,
                          aplanado.empty() ? *sym : aplanado.front().funcion,
                          atras_top, &*sym);
            /* Y en que se convirtio: la instruccion de la maquina que revento.
             * El fuente dice que se pedia; esta dice que se estaba haciendo, y
             * cuando no coinciden es justo lo que hay que ver.  Solo la del
             * marco de arriba: los de la cadena estan parados en una llamada y
             * no anaden nada. */
            {
                /* La ventana de codigo maquina.  Se descodifica desde el
                 * principio de la funcion porque las instrucciones son de
                 * tamano variable y no se puede retroceder. */
                /* En codigo compilado NO se ensena esto: son instrucciones
                 * de la maquina virtual, y lo que corrio fue codigo nativo.
                 * Ensenarlas seria dar por ejecutado algo que no lo fue. */
                /* Si lo que corrio fue codigo NATIVO se desensambla ESE, no
                 * el bytecode: son instrucciones distintas y ensenar las de la
                 * maquina virtual seria darlas por ejecutadas. */
                const std::vector<std::string> maq =
                    desde_compilado
                        ? native_window(vm, nat_pc, 3, 4)
                        : bytecode_window(vm, cur_pc - off_top, cur_pc, 3, 4);
                if (!maq.empty()) {
                    append_titulo("VX7018");
                    for (const std::string &t : maq) {
                        append_str("      ");
                        append(t.c_str(), t.size());
                        append_str("\n");
                    }
                } else if (!desde_compilado && vm->decoded_ptr &&
                           vm->decoded_ptr->metadata &&
                           vm->decoded_ptr->metadata->name) {
                    append_str("      maquina: ");
                    append_str(vm->decoded_ptr->metadata->name);
                    append_str("\n");
                }
            }
            /* Y las llamadas que el inlinado se comio.  No estan en la pila
             * -- por eso se aplanaron --, pero se hicieron, y sin ellas la
             * cadena salta de la funcion de dentro a la de fuera como si una
             * hubiera llamado a la otra directamente. */
            for (size_t k = 1; k < aplanado.size(); ++k) {
                append_str("  llamada desde ");
                const std::string nk = demangle_symbol(aplanado[k].funcion);
                append(nk.c_str(), nk.size());
                append_str(" [aplanado] (linea ");
                append_dec((uint64_t)aplanado[k - 1].linea);
                append_str(")\n");
            }
            if (!aplanado.empty()) {
                append_str("  llamada desde ");
                const std::string nf = demangle_symbol(*sym);
                append(nf.c_str(), nf.size());
                std::string arch_f;
                vxdbg::ContentHash res_f;
                const std::string nota_f =
                    entity_note_for_symbol(vm, *sym, &arch_f, &res_f);
                if (!nota_f.empty()) {
                    append_str(" [");
                    append(nota_f.c_str(), nota_f.size());
                    append_str("]");
                }
                append_str(" (linea ");
                append_dec((uint64_t)aplanado.back().linea);
                append_str(")\n");
                // Ya se conto: que el origen no lo repita.
                prev_origen = sym;
            }
        } else {
            append_str("<top> (pc=");
            append_hex(cur_pc);
            append_str(")\n");
        }
    }

    // Frames intermedios: recorrer frame_stack hasta el origen.
    // Limitamos a 64 frames para evitar runaway en casos degenerados.
    int depth = 0;
    /* Se empieza en el marco SIGUIENTE: el de arriba ya se conto.  Empezando en
     * `fr` salia repetido, y una pila cuyo primer marco aparece dos veces hace
     * dudar de todo lo demas que diga. */
    for (loader::FrameHeader *p = (fr ? fr->prev : nullptr);
         p != nullptr && depth < 64; p = p->prev, ++depth) {
        append_str("  at ");
        if (p->method) {
            const auto &mname = p->method->name;
            if (mname.data && mname.size > 0) {
                append((const char *)mname.data, mname.size);
            } else {
                append_str("<unknown>");
            }
            if (p->method->owner_class) {
                const auto &cname = p->method->owner_class->name;
                if (cname.data && cname.size > 0) {
                    append_str(" [");
                    append((const char *)cname.data, cname.size);
                    append_str("]");
                }
            }
            append_dbg(p->method, p->return_pc, "return_pc");
        } else {
            append_str("<frameless> (return_pc=");
            append_hex(p->return_pc);
            append_str(")");
        }
        append_str("\n");
    }
    if (depth >= 64) {
        append_str("  ... (truncated, depth >= 64)\n");
    }

    /* Cadena de llamadas por la PILA.  Los marcos de arriba solo cubren
     * METODOS registrados; el resto del camino -- una funcion libre, o un
     * metodo comptime, que al bajarse se vuelve un simbolo generado sin
     * `MethodInfo` detras -- se reconstruye mirando que direcciones guardadas
     * en la pila caen dentro de una funcion conocida.
     *
     * Es una lectura conservadora: puede colarse algun dato que por casualidad
     * parezca una direccion de retorno.  Preferible a no decir nada, que es lo
     * que habia.  Se van saltando las repeticiones seguidas del mismo simbolo
     * y se corta a 32 entradas. */
    /* Si lo que corrio fue codigo NATIVO, los marcos estan en la pila del
     * anfitrion y no en la de la maquina virtual: se recorre aquella. */
    if (desde_compilado) {
        uint64_t previo_va = UINT64_MAX;
        bool primero_n = true;
        for (const auto &marco :
             cadena_nativa(vm, vm->pending_fault_native_sp, 32)) {
            const uint64_t nat_n = marco.first;
            const uint64_t va = marco.second;
            if (va == previo_va) continue;
            previo_va = va;
            uint64_t off_n = 0;
            const std::string *sym_n = symbol_for_pc(vm, va, off_n);
            if (!sym_n) continue;
            /* La primera direccion de la pila es la de retorno de la llamada
             * en la que se esta: apunta a la MISMA funcion del marco de
             * arriba, que ya se conto.  Contarla otra vez la duplica. */
            if (primero_n) {
                primero_n = false;
                if (sym_top && *sym_top == *sym_n) continue;
            }
            if (prev_origen && *prev_origen == *sym_n) continue;
            prev_origen = sym_n;

            /* En que linea estaba este marco.  Se pregunta por el byte
             * ANTERIOR a la direccion de retorno, para caer dentro de la
             * llamada y no en lo que viene despues. */
            uint32_t linea_n = 0;
            (void)jit::lookup_line_by_native_pc(nat_n > 0 ? nat_n - 1 : 0,
                                                linea_n);
            /* Y que llamadas se aplanaron ahi.  Sin esto el marco lleva el
             * nombre de la funcion FISICA y una linea que puede ser de otra,
             * que es lo mismo que ya se corrigio para el marco de arriba y
             * para la cadena del interprete. */
            const std::vector<EscalonInline> apl_n =
                inline_chain_at(vm, *sym_n, linea_n, 0);

            append_str("  llamada desde ");
            const std::string leg_n =
                apl_n.empty() ? demangle_symbol(*sym_n)
                              : demangle_symbol(apl_n.front().funcion);
            append(leg_n.c_str(), leg_n.size());
            if (!apl_n.empty()) {
                append_str(" [aplanado en ");
                const std::string fis_n = demangle_symbol(*sym_n);
                append(fis_n.c_str(), fis_n.size());
                append_str("]");
            }
            std::string arch_n;
            vxdbg::ContentHash res_n;
            const std::string nota_n = entity_note_for_symbol(
                vm, apl_n.empty() ? *sym_n : apl_n.front().funcion, &arch_n,
                &res_n);
            if (!nota_n.empty()) {
                append_str(" [");
                append(nota_n.c_str(), nota_n.size());
                append_str("]");
            }
            if (linea_n > 0) {
                append_str(" (linea ");
                append_dec((uint64_t)linea_n);
                append_str(")");
            }
            append_str("\n");

            /* Las llamadas que el inlinado se comio por debajo de este marco.
             */
            for (size_t k = 1; k < apl_n.size(); ++k) {
                append_str("  llamada desde ");
                const std::string nk = demangle_symbol(apl_n[k].funcion);
                append(nk.c_str(), nk.size());
                append_str(" [aplanado] (linea ");
                append_dec((uint64_t)apl_n[k - 1].linea);
                append_str(")\n");
            }
            if (!apl_n.empty()) {
                append_str("  llamada desde ");
                const std::string nf_n = demangle_symbol(*sym_n);
                append(nf_n.c_str(), nf_n.size());
                /* La nota de arriba describe a la funcion aplanada; esta es la
                 * FISICA y hay que preguntarla aparte. */
                std::string arch_g;
                vxdbg::ContentHash res_g;
                const std::string nota_g =
                    entity_note_for_symbol(vm, *sym_n, &arch_g, &res_g);
                if (!nota_g.empty()) {
                    append_str(" [");
                    append(nota_g.c_str(), nota_g.size());
                    append_str("]");
                }
                append_str(" (linea ");
                append_dec((uint64_t)apl_n.back().linea);
                append_str(")\n");
            }
        }
    }

    {
        const uint64_t rsp = vm->registers.stack_pointer.qword();
        const uint64_t top = vm->stack_high;
        const std::string *prev = nullptr;
        int shown = 0;
        for (uint64_t a2 = rsp; a2 + 8 <= top && shown < 32; a2 += 8) {
            uint64_t v = 0;
            vm->vm_mem.read_bytes(a2, &v, sizeof(v));
            if (v == 0) continue;
            uint64_t off = 0;
            const std::string *sym = symbol_for_pc(vm, v, off);
            if (!sym || off > 0x10000) continue; /* fuera de toda funcion */
            /* `code.s_N` son literales de datos, no codigo: un valor que cae
             * ahi es un dato que se parece a una direccion, no una llamada. */
            if (sym->rfind("code.s_", 0) == 0) continue;
            /* `gdata.*` es el area de variables globales, tampoco codigo. */
            if (sym->rfind("gdata.", 0) == 0) continue;
            if (prev && *prev == *sym) continue;
            prev = sym;
            prev_origen = sym;
            /* Aqui tambien puede haber llamadas aplanadas: la direccion de
             * retorno cae en una funcion, pero la linea a la que corresponde
             * puede ser de otra que se inlino dentro.  Sin mirarlo, el marco
             * lleva un nombre y debajo una linea que no es suya. */
            const std::vector<EscalonInline> apl2 =
                inline_chain_at(vm, *sym, linea_de_pc(v, 1), 0);
            append_str("  llamada desde ");
            const std::string legible =
                apl2.empty() ? demangle_symbol(*sym)
                             : demangle_symbol(apl2.front().funcion);
            append(legible.c_str(), legible.size());
            if (!apl2.empty()) {
                append_str(" [aplanado en ");
                const std::string fis2 = demangle_symbol(*sym);
                append(fis2.c_str(), fis2.size());
                append_str("]");
            }
            /* Cada marco de la cadena tambien dice QUE es y con que firma: sin
             * ella, dos sobrecargas del mismo nombre son indistinguibles justo
             * cuando hay que saber por cual se paso. */
            std::string archivo2;
            vxdbg::ContentHash resumen2;
            const std::string nota2 = entity_note_for_symbol(
                vm, apl2.empty() ? *sym : apl2.front().funcion, &archivo2,
                &resumen2);
            if (!nota2.empty()) {
                append_str(" [");
                append(nota2.c_str(), nota2.size());
                append_str("]");
            }
            append_pos(v, legible.find('.') != std::string::npos);
            append_str("\n");
            append_source(v, archivo2, resumen2,
                          apl2.empty() ? *sym : apl2.front().funcion, 1, &*sym);
            /* Y las llamadas que el inlinado se comio por debajo de este
             * marco, igual que en el de arriba. */
            for (size_t k = 1; k < apl2.size(); ++k) {
                append_str("  llamada desde ");
                const std::string nk = demangle_symbol(apl2[k].funcion);
                append(nk.c_str(), nk.size());
                append_str(" [aplanado] (linea ");
                append_dec((uint64_t)apl2[k - 1].linea);
                append_str(")\n");
            }
            if (!apl2.empty()) {
                append_str("  llamada desde ");
                const std::string nf2 = demangle_symbol(*sym);
                append(nf2.c_str(), nf2.size());
                if (!nota2.empty()) {
                    /* La nota de arriba describe a la funcion aplanada; esta
                     * es la fisica y hay que preguntarla aparte. */
                    std::string arch_g;
                    vxdbg::ContentHash res_g;
                    const std::string nota_g =
                        entity_note_for_symbol(vm, *sym, &arch_g, &res_g);
                    if (!nota_g.empty()) {
                        append_str(" [");
                        append(nota_g.c_str(), nota_g.size());
                        append_str("]");
                    }
                }
                append_str(" (linea ");
                append_dec((uint64_t)apl2.back().linea);
                append_str(")\n");
            }
            ++shown;
        }
    }

    /* El ORIGEN de la ejecucion, si no salio ya.
     *
     * La cadena se reconstruye con las direcciones de retorno que hay en la
     * pila, y el punto de entrada no tiene ninguna: nadie lo llamo.  Cuando
     * por medio hay llamadas que no dejan su retorno donde el barrido mira
     * -- los metodos --, la cadena se corta antes de llegar y la traza acaba
     * sin decir de donde venia todo.  El proceso si lo sabe, y lo dice. */
    if (vm->entry_pc != UINT64_MAX) {
        uint64_t off_e = 0;
        const std::string *sym_e = symbol_for_pc(vm, vm->entry_pc, off_e);
        // Si el barrido ya lo conto, no repetirlo.
        if (sym_e && !(prev_origen && *prev_origen == *sym_e)) {
            append_str("  origen ");
            const std::string legible_e = demangle_symbol(*sym_e);
            append(legible_e.c_str(), legible_e.size());
            std::string archivo_e;
            vxdbg::ContentHash resumen_e;
            const std::string nota_e =
                entity_note_for_symbol(vm, *sym_e, &archivo_e, &resumen_e);
            if (!nota_e.empty()) {
                append_str(" [");
                append(nota_e.c_str(), nota_e.size());
                append_str("]");
            }
            append_str("\n");
        }
    }

    // Pid del proceso para diagnostico cross-process.
    append_str("  in process pid=");
    append_dec(vm->pid.local_pid);
    append_str(" sched=");
    append_dec(vm->pid.scheduler_id);
    append_str("\n");

    out[pos] = '\0';
    return pos;
}

// ---------------------------------------------------------------------
// Helper interno: asegura que vm tiene los buffers reservados.
// Lazy alloc en el primer throw_fatal del proceso.
// ---------------------------------------------------------------------

static void ensure_fatal_buffers(ProcessVM *vm) {
    if (!vm->fatal_slot) {
        vm->fatal_slot = std::calloc(1, FATAL_SLOT_SIZE);
    }
    if (!vm->fatal_msg_buf) {
        vm->fatal_msg_buf = (char *)std::malloc(256);
        if (vm->fatal_msg_buf) vm->fatal_msg_buf[0] = '\0';
    }
    if (!vm->fatal_trace_buf) {
        vm->fatal_trace_buf = (char *)std::malloc(4096);
        if (vm->fatal_trace_buf) vm->fatal_trace_buf[0] = '\0';
    }
}

// ---------------------------------------------------------------------
// Forward decl: do_throw vive en exec_instruction_oop.cpp.
// ---------------------------------------------------------------------
void do_throw(ProcessVM *vm, uint64_t exception_ptr);

/**
 * @brief Mapea FATAL_* a state_err_thread para la ruta antigua.
 */
static state_err_thread fatal_to_thread_err(uint32_t kind) noexcept {
    switch (kind) {
    case FATAL_NULL_POINTER: return THREAD_NULL_POINTER;
    case FATAL_DIVISION_BY_ZERO: return THREAD_DIVISION_BY_ZERO;
    case FATAL_STACK_OVERFLOW: return THREAD_STACK_OVERFLOW;
    case FATAL_STACK_UNDERFLOW: return THREAD_STACK_UNDERFLOW;
    case FATAL_ILLEGAL_INSTRUCTION: return THREAD_ILLEGAL_INSTRUCTION;
    case FATAL_INVALID_SYSCALL: return THREAD_INVALID_SYSCALL;
    case FATAL_SEGMENTATION_FAULT: return THREAD_SEGMENTATION_FAULT;
    default: return THREAD_SEGMENTATION_FAULT;
    }
}

// ---------------------------------------------------------------------
// throw_fatal: ruta dual (capturable / fatal-original).
// ---------------------------------------------------------------------

void report_uncaught_exception(ProcessVM *vm, const char *class_name) {
    /* Sale con codigo distinto de cero por la misma razon que `panic`: el
     * programa se rindio.  Sin esto el proceso afirmaba haber terminado bien.
     */
    g_last_fatal_kind.store(FATAL_USER_ABORT, std::memory_order_relaxed);
    /* Con el nombre ESCRITO, no el aplanado: la traza de al lado dice
     * `atr.hondo`, y decir aqui `atr__MiExc` obliga a traducir a mano. */
    const std::string texto = vx::diag::format(
        "VX7026", {class_name ? demangle_symbol(class_name) : "?"});
    std::fprintf(stderr, "\n%s [VX7026]\n", texto.c_str());
    /* La traza se saca AQUI, con la cadena de marcos todavia en pie; quien
     * llama la desmonta despues. */
    ensure_fatal_buffers(vm);
    if (vm->fatal_trace_buf) {
        build_stack_trace(vm, vm->fatal_trace_buf, 4096);
        if (vm->fatal_trace_buf[0] != '\0')
            std::fprintf(stderr, "%s", vm->fatal_trace_buf);
    }
    std::fflush(stderr);
}

void throw_fatal(ProcessVM *vm, uint32_t kind, const char *message,
                 bool catchable) {
    if (!vm) return;

    // Notificar al debugger de la excepcion ANTES de elegir ruta
    // (capturable o fatal).  El cliente recibe evento "exception"
    // con clase + pid; util para parar y ver el contexto incluso
    // si el codigo del usuario captura la excepcion.  Si no hay
    // debugger activo (caso comun), la rama es 1 carga + 1 branch
    // bien predicho (~0 ns en hot path).
    if (vm->scheduler.vm_reference.debugger != nullptr) {
        vm->scheduler.vm_reference.debugger->on_exception(
            vm->pid.local_pid,
            message ? std::string(message) : std::string("FatalError"));
    }

    // FAST PATH: si no hay handler activo, ruta antigua.  Esto es
    // el caso comun (programas sin try/catch envolvente).  Cero
    // overhead anadido: 1 lectura + 1 branch.
    //
    // Y tambien se toma cuando el fallo NO es capturable, haya `try` o no:
    // ver el parametro `catchable` en la cabecera.
    if (vm->exc_frame_stack == nullptr || !catchable) {
        /* Guardar el mensaje aunque no haya quien lo capture.  Antes solo se
         * conservaba en la ruta CON handler, asi que un fallo sin `try` se
         * llevaba consigo la unica pista de que habia pasado.  Quien recoja
         * el cadaver del proceso -- el compilador, cuando esto ocurre durante
         * una ejecucion comptime -- necesita poder decirlo. */
        ensure_fatal_buffers(vm);
        if (vm->fatal_msg_buf) {
            if (message) {
                std::strncpy(vm->fatal_msg_buf, message, 255);
                vm->fatal_msg_buf[255] = '\0';
            } else {
                vm->fatal_msg_buf[0] = '\0';
            }
        }
        /* La traza se construye AQUI, con el proceso todavia coherente.
         * Hacerlo despues, cuando alguien recoge el cadaver, significa
         * recorrer una cadena de marcos que ya no tiene por que ser valida --
         * y eso se lleva por delante a quien lo intente. */
        if (vm->fatal_trace_buf) {
            build_stack_trace(vm, vm->fatal_trace_buf, 4096);
        }
        /* Y se ENSEÑA.  Guardarlo sin decir nada dejaba al programa parandose
         * en seco: sin mensaje, sin traza y con codigo de salida cero, o sea
         * afirmando que todo fue bien.  Cualquier guion o integracion continua
         * que lo llamara se lo creia.  Un fallo que nadie captura es lo mas
         * parecido a un error de verdad que hay, y tiene que verse. */
        informar_del_fallo(vm, kind, false);
        vm->err_thread = fatal_to_thread_err(kind);
        vm->scheduler.on_event(EVT_ERROR);
        return;
    }

    // Si por algun motivo la clase FatalError no esta registrada
    // (init_exception_classes no se llamo), no podemos lanzar como
    // excepcion -- caemos al camino antiguo.
    if (g_fatal_error_class == nullptr) {
        vm->err_thread = fatal_to_thread_err(kind);
        vm->scheduler.on_event(EVT_ERROR);
        return;
    }

    // SLOW PATH (handler activo): construir la instancia FatalError.
    ensure_fatal_buffers(vm);
    if (!vm->fatal_slot) {
        // OOM en el slot mismo: ruta antigua.
        vm->err_thread = fatal_to_thread_err(kind);
        vm->scheduler.on_event(EVT_ERROR);
        return;
    }

    // Inicializar ObjectHeader.
    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(vm->fatal_slot);
    std::memset(hdr, 0, sizeof(loader::ObjectHeader));
    hdr->class_ptr = g_fatal_error_class;
    hdr->flags = 0;
    hdr->hash_code = 0;

    // Llenar fields por offset directo.
    char *base = (char *)vm->fatal_slot;
    const uint64_t pc_now = vm->registers.rip.raw();
    *(uint64_t *)(base + FATAL_OFF_KIND) = (uint64_t)kind;
    *(uint64_t *)(base + FATAL_OFF_PC) = pc_now;

    // Copiar mensaje al buffer reusable (truncar a 255).
    if (vm->fatal_msg_buf && message) {
        std::strncpy(vm->fatal_msg_buf, message, 255);
        vm->fatal_msg_buf[255] = '\0';
    }
    *(uint64_t *)(base + FATAL_OFF_MSG_PTR) =
        (uint64_t)(uintptr_t)vm->fatal_msg_buf;

    // Construir stack trace (ya incluye el PC y los frames).
    if (vm->fatal_trace_buf) {
        build_stack_trace(vm, vm->fatal_trace_buf, 4096);
    }
    *(uint64_t *)(base + FATAL_OFF_TRACE_PTR) =
        (uint64_t)(uintptr_t)vm->fatal_trace_buf;

    /* Y se cuenta, aunque haya quien lo recoja.  El fallo ocurrio: que el
     * programa tenga un `try` alrededor decide si SIGUE, no si se supo.  Antes
     * el informe colgaba de no haber handler, asi que rodear de `try` una
     * averia la volvia invisible -- y con ella la unica forma de saber donde
     * estaba.  Morir sigue siendo cosa de nadie haberlo capturado. */
    informar_del_fallo(vm, kind, true);

    // Lanzar via do_throw (mismo patron que `throw new X` en bytecode).
    do_throw(vm, (uint64_t)(uintptr_t)vm->fatal_slot);
}

// ---------------------------------------------------------------------
// exec_instr_panic: lee mensaje de la VM y lanza FATAL_USER_ABORT.
// ---------------------------------------------------------------------

// =====================================================================
// OS-level access violation -> FatalError capturable.
// =====================================================================

// Thread-local: ProcessVM cuyo bytecode esta corriendo.  El handler
// de AV/SIGSEGV lo consulta para identificar el receptor del longjmp.
// Limitacion: el VM corre cada proceso en su scheduler, asi que un
// mismo OS thread tiene UN ProcessVM activo a la vez.  Si en el
// futuro se anade preemption con context-switch dentro del run_loop,
// habria que actualizar el TLS antes de cambiar de proceso.
/* Se guarda en una ranura NUESTRA (`util::ThreadSlot`) y no en un `__thread`.
 *
 * Motivo, medido: en MinGW `__thread` es TLS EMULADA y cada acceso es una
 * llamada a `__emutls_get_address`, que por dentro hace `TlsGetValue` mas
 * guardar y restaurar el ultimo error.  Perfilando la ejecucion de un banco de
 * despacho, esa maquinaria salia al 9,5% del tiempo, y sus dos usuarios eran
 * `vrt_callitf` y esto, que se toca en CADA entrada al JIT.  Un acceso pasa de
 * 10,83 ns a 0,65.
 *
 * Y ademas se deja de hacer el trabajo dos veces: antes esto convivia con un
 * slot dedicado de `TlsAlloc` -- el que lee el thunk -- y habia que escribir en
 * los dos y mantenerlos sincronizados.  Ahora hay UNO. */
#if defined(_WIN32)
static util::ThreadSlot g_proc_slot;
#else
/* Fuera de Windows NO se toca: `__thread` ahi ES TLS de verdad -- una lectura
 * directa, sin llamada -- y ademas es segura dentro de un manejador de senal,
 * cosa que pasar por la API de claves no garantiza.  El problema es de MinGW,
 * asi que el arreglo se queda en MinGW. */
static __thread ProcessVM *t_executing_proc = nullptr;
#endif

#if defined(_WIN32)
/* Sprint JIT thunk TLS-direct (Win64 only):
 *
 * Reservamos UN slot TLS dedicado via TlsAlloc().  El thunk
 * x86-64 generado lee proc directamente via @c gs:[0x1480 + idx*8]
 * (slots 0..63 viven embebidos en el TEB).  Coste: 1 instr ~3 ns
 * vs 25-30 ns del call a @c get_current_executing_process.
 *
 * El offset 0x1480 corresponde a TlsSlots[0] dentro del TEB en
 * Win64 (verificable en wikipedia.org/wiki/Win32_Thread_Information_Block).
 * Slots >= 64 estan en TlsExpansionSlots accesibles via
 * @c gs:[0x1780] + indirect; el thunk los rechaza y cae al call. */
unsigned long jit_proc_tls_index() noexcept {
    g_proc_slot.ensure();
    return static_cast<unsigned long>(g_proc_slot.slot_index());
}
#endif

void set_current_executing_process(ProcessVM *proc) noexcept {
#if defined(_WIN32)
    /* Una sola escritura.  El thunk lee ESTA misma ranura por su cuenta, asi
     * que ya no hay dos sitios que mantener sincronizados. */
    g_proc_slot.ensure();
    g_proc_slot.set(proc);
#else
    t_executing_proc = proc;
#endif
}

ProcessVM *get_current_executing_process() noexcept {
#if defined(_WIN32)
    return static_cast<ProcessVM *>(g_proc_slot.get());
#else
    return t_executing_proc;
#endif
}

} // namespace runtime

/* Sprint JIT-cross-fn 2026-06-01: extern "C" shim para que el header
 * publico `jit/interp_jit_bridge.h` pueda invocar
 * `set_current_executing_process` sin necesitar incluir
 * `runtime/exception_runtime.h` (que arrastraria todo el runtime).  El shim es
 * solo un wrapper de 1 line. */
extern "C" void runtime_set_current_executing_process_c(void *proc) {
    runtime::set_current_executing_process(
        static_cast<runtime::ProcessVM *>(proc));
}

namespace runtime {

static std::once_flag g_av_handler_init_flag;

#if defined(_WIN32)
/// Handle del VEH instalado por ::install_host_av_handler.  Se guarda para
/// poder retirarlo (::uninstall_host_av_handler) ANTES de que el codigo de la
/// libreria quede sin mapear: si libvesta se descarga (FreeLibrary) sin retirar
/// el VEH, la cadena de manejadores conserva un puntero a codigo muerto y el
/// cierre del proceso (o cualquier excepcion posterior) salta a esa direccion
/// -> segfault.
static void *g_av_veh_handle = nullptr;
#endif

#if defined(_WIN32)
/**
 * @brief Stub al que el VEH redirige RIP cuando ocurre un AV
 *        capturable.  Corre en contexto de usuario normal (no async)
 *        asi que el longjmp es seguro aqui.
 *
 * Marcado @c noinline para que el compilador no inline el contenido
 * en otro punto del binary -- queremos una direccion estable que el
 * VEH pueda apuntar.
 */
static void __attribute__((noinline)) av_recovery_stub() {
    /* Leer la ranura propia y no un `__thread`: dentro de un manejador de
     * excepciones importa que esto no pueda bloquearse ni pedir memoria, y la
     * TLS emulada de MinGW hace las dos cosas en el primer acceso. */
    ProcessVM *proc = runtime::get_current_executing_process();
    if (proc != nullptr && proc->av_recovery_active) {
        std::longjmp(proc->av_recovery_jmpbuf, 1);
    }
    // Sin recovery activo: no podemos hacer nada utilidad; salir.
    // En la practica esto no deberia ocurrir porque el VEH ya
    // verifica av_recovery_active antes de redirigir.
    std::abort();
}

/**
 * @brief Vectored Exception Handler global.  Solo trata
 *        EXCEPTION_ACCESS_VIOLATION cuando el thread actual esta
 *        ejecutando bytecode con un try/catch envolvente.  En todos
 *        los demas casos retorna EXCEPTION_CONTINUE_SEARCH para no
 *        interferir con el manejo normal de excepciones (otros
 *        plugins, debugger, etc.).
 */
static LONG WINAPI vx_av_veh(EXCEPTION_POINTERS *info) {
    if (info == nullptr || info->ExceptionRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    // Manejamos AV y divisiones por cero (Bug fix 2026-05-23).
    // Otras excepciones (illegal instr, debug breakpoints, etc.) siguen
    // su curso normal.
    /* TODO FALLO SE CUENTA.  Antes solo se trataban tres codigos y cualquier
     * otro seguia su curso, o sea que el proceso moria SIN DECIR NADA -- ni
     * codigo, ni linea, ni cadena de llamadas --.  Eso obliga a buscar a mano
     * lo que la maquina ya sabia, y es lo peor que puede hacer un runtime.
     * Pasa de verdad: la biblioteca de memoria trae variantes con AVX-512, y
     * llamarlas en un procesador que no lo tiene levanta una instruccion
     * ilegal que no estaba en la lista.
     *
     * Lo que SI sigue su curso es lo que no es un fallo: los puntos de ruptura
     * y el paso a paso son del depurador, y las excepciones de C++ son control
     * de flujo normal de la propia VM.  Quedarselas romperia a quien las
     * espera. */
    switch (code) {
    case EXCEPTION_BREAKPOINT:
    case EXCEPTION_SINGLE_STEP:
    case 0xE06D7363u: // excepcion de C++ (msvc/mingw)
    case 0x406D1388u: // nombre de hilo para el depurador
        return EXCEPTION_CONTINUE_SEARCH;
    default: break;
    }
    uint32_t kind_local; // 0=AV 1=div0 2=overflow 3=instr ilegal 4=lo demas
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        kind_local = 0;
    } else if (code == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        kind_local = 1;
    } else if (code == EXCEPTION_INT_OVERFLOW) {
        kind_local = 2;
    } else if (code == EXCEPTION_ILLEGAL_INSTRUCTION ||
               code == EXCEPTION_PRIV_INSTRUCTION) {
        kind_local = 3;
    } else {
        kind_local = 4;
    }
    ProcessVM *proc = runtime::get_current_executing_process();
    if (proc == nullptr || !proc->av_recovery_active) {
        // No hay bytecode corriendo o el scheduler no ha armado el
        // setjmp: la VM crashea como antes (comportamiento legado).
        return EXCEPTION_CONTINUE_SEARCH;
    }
    /* Gana el PRIMER fallo, no el ultimo.  Al desviar la ejecucion al stub de
     * recuperacion desde codigo compilado, el desvio puede provocar un segundo
     * fallo antes de que nadie haya leido el primero; si se sobrescribiera, una
     * division entre cero acabaria contandose como acceso invalido -- que es
     * exactamente lo que pasaba en JIT.  El que hay que explicar es el que
     * rompio el programa, no el que provoco el intento de recuperarlo. */
    const bool primero = (proc->pending_av_kind == 0xFFFFFFFFu);
    if (!primero) {
        /* Ya se estaba atendiendo un fallo y ha llegado otro: casi seguro,
         * construyendo el informe del primero.  Desviar otra vez al stub seria
         * volver al mismo punto de recuperacion, empezar de cero a atender el
         * primero, fallar de nuevo en el mismo sitio y no salir nunca.  Un
         * programa colgado sin decir nada es peor que uno que muere diciendolo,
         * asi que se suelta la recuperacion y el fallo sigue su curso. */
        proc->av_recovery_active = false;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    /* La direccion NATIVA del fallo, antes de tocarla mas abajo para desviar
     * la ejecucion.  En codigo compilado es el unico dato fiable de donde
     * ocurrio: el PC de la maquina virtual no se va actualizando ahi. */
    if (primero && info->ContextRecord) {
#if defined(_M_X64) || defined(__x86_64__)
        proc->pending_fault_native_pc = (uint64_t)info->ContextRecord->Rip;
        // Y por donde iba la pila NATIVA: los marcos de la cadena viven ahi.
        proc->pending_fault_native_sp = (uint64_t)info->ContextRecord->Rsp;
        /* Y el resto del banco, en el orden de la codificacion x86-64.  El
         * sistema lo entrega entero; quedarse solo con el PC obliga despues a
         * ensenar que instruccion revento sin poder decir con que valores. */
        const CONTEXT *c = info->ContextRecord;
        const uint64_t banco[16] = {
            c->Rax, c->Rcx, c->Rdx, c->Rbx, c->Rsp, c->Rbp, c->Rsi, c->Rdi,
            c->R8,  c->R9,  c->R10, c->R11, c->R12, c->R13, c->R14, c->R15};
        for (int k = 0; k < 16; ++k)
            proc->pending_fault_native_regs[k] = banco[k];
        proc->pending_fault_native_regs_ok = true;
#elif defined(_M_IX86) || defined(__i386__)
        proc->pending_fault_native_pc = (uint64_t)info->ContextRecord->Eip;
        proc->pending_fault_native_sp = (uint64_t)info->ContextRecord->Esp;
#endif
    }
    if (primero) {
        proc->pending_av_kind = kind_local;
        // El codigo del sistema viaja: sin el, un fallo que no esta en la lista
        // se cuenta pero no se puede identificar.
        proc->pending_av_os_code = (uint64_t)code;
    }
    // Capturar la direccion del fault (segundo elemento de
    // ExceptionInformation: 0=read/write flag, 1=virtual addr) -- solo
    // para AV; para div0 / overflow no aplica.
    //
    // Para una instruccion que el procesador no tiene, y para lo que no esta en
    // la lista, la direccion que importa NO es un dato: es donde esta la propia
    // instruccion.  Esa la da `ExceptionAddress`, y sin ella el mensaje decia
    // "en la direccion 0x0", que es no decir nada.
    if (primero && kind_local == 0 &&
        info->ExceptionRecord->NumberParameters >= 2) {
        proc->pending_av_addr =
            (uint64_t)info->ExceptionRecord->ExceptionInformation[1];
    } else if (primero && (kind_local == 3 || kind_local == 4)) {
        proc->pending_av_addr =
            (uint64_t)(uintptr_t)info->ExceptionRecord->ExceptionAddress;
    } else if (primero) {
        proc->pending_av_addr = 0;
    }
    /* Se salta al stub, que hara el salto largo ya en contexto normal.
     *
     * Y se entra COMO SI SE LE HUBIERA LLAMADO: se baja la pila y se deja
     * arriba la direccion donde ocurrio el fallo, haciendo de direccion de
     * retorno.  Antes se cambiaba solo el puntero de instruccion y se reusaba
     * la pila tal cual, y eso deja al stub en un marco que no existe: en la
     * cima no habia ninguna direccion de retorno, sino lo que hubiera ahi.
     *
     * En Windows importa porque el salto largo es un DESENROLLADO por tablas:
     * el sistema camina la pila marco a marco, y el primero que lee es el del
     * stub.  Con la cima ocupada por un dato cualquiera se iba a parar a
     * cualquier sitio, asi que un fallo dentro de un bloque de ensamblador se
     * recuperaba o se llevaba el proceso segun como hubiera quedado la pila --
     * reproducible con la longitud de la ruta del ejecutable.  Con la direccion
     * de retorno puesta, el desenrollado sale del stub a la funcion que fallo y
     * de ahi a sus llamadores, que es lo que tiene que hacer.
     *
     * La pila se alinea a 16 antes de bajar los 8 de la direccion, que es
     * exactamente como queda tras un `call`. */
#if defined(_M_X64) || defined(__x86_64__)
    {
        DWORD64 rsp = info->ContextRecord->Rsp;
        rsp &= ~(DWORD64)0xF;
        rsp -= 8;
        *reinterpret_cast<DWORD64 *>((uintptr_t)rsp) = info->ContextRecord->Rip;
        info->ContextRecord->Rsp = rsp;
    }
    info->ContextRecord->Rip = (DWORD64)(uintptr_t)&av_recovery_stub;
#elif defined(_M_IX86) || defined(__i386__)
    info->ContextRecord->Eip = (DWORD)(uintptr_t)&av_recovery_stub;
#elif defined(_M_ARM64) || defined(__aarch64__)
    info->ContextRecord->Pc = (DWORD64)(uintptr_t)&av_recovery_stub;
#else
    // Plataforma desconocida: dejar que la VM crashee como antes.
    return EXCEPTION_CONTINUE_SEARCH;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}

void install_host_av_handler() noexcept {
    std::call_once(g_av_handler_init_flag, []() {
        // Primer parametro = 1 -> registrar al inicio de la cadena
        // (antes del default Windows handler).  Asi capturamos AVs
        // antes de que llegue el "Application has stopped" del OS.
        // Guardamos el handle para poder retirarlo al descargar la libreria.
        g_av_veh_handle = AddVectoredExceptionHandler(1u, &vx_av_veh);
    });
}

void uninstall_host_av_handler() noexcept {
    // Retirar el VEH.  Imprescindible si libvesta se descarga con FreeLibrary:
    // tras desmapear la DLL, un VEH colgante apuntaria a codigo muerto.
    if (g_av_veh_handle) {
        RemoveVectoredExceptionHandler(g_av_veh_handle);
        g_av_veh_handle = nullptr;
    }
}
#else
// POSIX: handler de SIGSEGV / SIGFPE.  El handler usa siglongjmp directamente
// ya que en POSIX longjmp desde un signal handler es bien definido
// si se usa sigsetjmp con savesigs=1.
static void posix_signal_handler(int sig, siginfo_t *info, void *ctx) {
    ProcessVM *proc = t_executing_proc;
    if (proc == nullptr || !proc->av_recovery_active) {
        std::signal(sig, SIG_DFL);
        std::raise(sig);
        return;
    }
    /* Solo el PRIMER fallo cuenta, como en Windows.
     *
     * Construir el informe toca memoria -- desensambla el codigo que revento,
     * recorre la cadena de marcos --, y si eso vuelve a fallar el segundo
     * fallo pisaba al primero: el programa terminaba diciendo "acceso a memoria
     * invalido" cuando lo que habia pasado era una instruccion que el
     * procesador no tiene.  Contar el segundo y callar el primero es contar el
     * sintoma en vez de la causa. */
    if (proc->pending_av_kind != 0xFFFFFFFFu) {
        /* Ya se estaba atendiendo un fallo y ha ocurrido otro: casi seguro,
         * construyendo el informe del primero.  Volver al mismo punto de
         * recuperacion seria empezar de cero a atender el primero, fallar otra
         * vez en el mismo sitio y no salir nunca -- el programa se quedaba
         * colgado sin decir nada, que es peor que morir diciendolo.
         *
         * Asi que se suelta la recuperacion y se deja que el fallo siga su
         * curso: el sistema termina el proceso y lo cuenta el.  Se pierde el
         * informe bonito del primero, pero no se pierde el programa. */
        proc->av_recovery_active = false;
        std::signal(sig, SIG_DFL);
        std::raise(sig);
        return;
    }
    /* El estado de la maquina al fallar.
     *
     * Aqui se tiraba: el tercer argumento se ignoraba con un `(void)ctx`.  Y es
     * el mismo dato que en Windows se recoge entero, asi que el mismo programa
     * fallando contaba MENOS en Linux -- sin la instruccion culpable, sin el
     * rasgo que exige, y en codigo compilado sin siquiera saber en que funcion
     * estaba, porque el puntero de instruccion de la maquina virtual no se va
     * actualizando ahi.  Un fallo no puede contarse mejor o peor segun el
     * sistema donde ocurra. */
#if defined(__x86_64__)
    if (ctx != nullptr) {
        const auto *uc = reinterpret_cast<const ucontext_t *>(ctx);
        const auto *g = uc->uc_mcontext.gregs;
        proc->pending_fault_native_pc = (uint64_t)g[REG_RIP];
        proc->pending_fault_native_sp = (uint64_t)g[REG_RSP];
        /* En el orden de la codificacion x86-64, el mismo que espera quien lo
         * lee (`indice_de_reg_x86`).  `gregs` NO va en ese orden. */
        const uint64_t banco[16] = {
            (uint64_t)g[REG_RAX], (uint64_t)g[REG_RCX], (uint64_t)g[REG_RDX],
            (uint64_t)g[REG_RBX], (uint64_t)g[REG_RSP], (uint64_t)g[REG_RBP],
            (uint64_t)g[REG_RSI], (uint64_t)g[REG_RDI], (uint64_t)g[REG_R8],
            (uint64_t)g[REG_R9],  (uint64_t)g[REG_R10], (uint64_t)g[REG_R11],
            (uint64_t)g[REG_R12], (uint64_t)g[REG_R13], (uint64_t)g[REG_R14],
            (uint64_t)g[REG_R15]};
        for (int k = 0; k < 16; ++k)
            proc->pending_fault_native_regs[k] = banco[k];
        proc->pending_fault_native_regs_ok = true;
    }
#elif defined(__i386__)
    if (ctx != nullptr) {
        const auto *uc = reinterpret_cast<const ucontext_t *>(ctx);
        proc->pending_fault_native_pc =
            (uint64_t)uc->uc_mcontext.gregs[REG_EIP];
        proc->pending_fault_native_sp =
            (uint64_t)uc->uc_mcontext.gregs[REG_ESP];
    }
#else
    (void)ctx;
#endif
    // Bug fix 2026-05-23: capturar tambien SIGFPE (div/0).
    if (sig == SIGFPE) {
        proc->pending_av_kind = 1; // DIVIDE_BY_ZERO (o overflow)
        proc->pending_av_addr = 0;
    } else if (sig == SIGILL) {
        /* Instruccion que este procesador no sabe ejecutar.  Sin esto el
         * proceso moria por la via legada, sin codigo ni linea ni cadena de
         * llamadas -- justo lo que obliga a buscar a mano lo que la maquina ya
         * sabia. */
        proc->pending_av_kind = 3;
        proc->pending_av_addr = info ? (uint64_t)(uintptr_t)info->si_addr : 0;
    } else if (sig == SIGSEGV || sig == SIGBUS) {
        proc->pending_av_kind = 0; // AV
        proc->pending_av_addr = info ? (uint64_t)(uintptr_t)info->si_addr : 0;
    } else {
        // Cualquier otra: se cuenta igual.  Callarsela deja al proceso morir
        // sin decir nada, que es justo lo que hay que evitar.
        proc->pending_av_kind = 4;
        proc->pending_av_addr = info ? (uint64_t)(uintptr_t)info->si_addr : 0;
    }
    proc->pending_av_os_code = (uint64_t)sig;
    std::longjmp(proc->av_recovery_jmpbuf, 1);
}

void install_host_av_handler() noexcept {
    std::call_once(g_av_handler_init_flag, []() {
        struct sigaction sa{};
        sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
        sa.sa_sigaction = &posix_signal_handler;
        sigemptyset(&sa.sa_mask);
        (void)sigaction(SIGSEGV, &sa, nullptr);
        (void)sigaction(SIGBUS, &sa, nullptr);
        (void)sigaction(SIGFPE, &sa, nullptr);
        (void)sigaction(SIGILL, &sa, nullptr);
    });
}

void uninstall_host_av_handler() noexcept {
    // Restaurar el comportamiento por defecto para que, si la libreria se
    // descarga (dlclose), no quede un handler apuntando a codigo desmapeado.
    std::signal(SIGSEGV, SIG_DFL);
    std::signal(SIGBUS, SIG_DFL);
    std::signal(SIGFPE, SIG_DFL);
}
#endif

} // namespace runtime

// Definicion del exec_instr fuera del namespace runtime para matchear
// la declaracion en runtime/exec_instruction.h (que usa namespace runtime
// implicitamente al ser includado en archivos que ya estan en namespace
// runtime).  Pero para mantener consistencia con los otros exec_instr_*,
// va dentro del namespace runtime tambien.

namespace runtime {

/**
 * @brief Layout de SetMethDebugParams (24 bytes en VM mem).
 */
struct SetMethDebugParams {
    uint64_t method_ptr;
    uint64_t file_addr;
    uint32_t file_len;
    uint32_t start_line;
};

void exec_instr_setmethdbg(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_method = instr.data_instruction.reg_data.reg1;
    const uint8_t r_params = instr.data_instruction.reg_data.reg2;
    (void)r_method; // por ahora usamos solo el params (que tambien
                    // lleva method_ptr); r_method redundante para
                    // futuros usos del decoder.

    const uint64_t params_addr = vm->registers.regs[r_params].qword();
    if (params_addr == 0) return;

    SetMethDebugParams sp{};
    vm->vm_mem.read_bytes(params_addr, &sp, sizeof(sp));
    if (sp.method_ptr == 0) return;

    // Leer nombre de archivo del VM mem (truncar a 256 bytes).
    char fbuf[256];
    size_t flen = (size_t)sp.file_len;
    if (flen > 255) flen = 255;
    if (sp.file_addr != 0 && flen > 0) {
        vm->vm_mem.read_bytes(sp.file_addr, fbuf, flen);
    }
    fbuf[flen] = '\0';

    register_method_debug(reinterpret_cast<loader::MethodInfo *>(sp.method_ptr),
                          fbuf, flen, sp.start_line);
}

void exec_instr_panic(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_addr = instr.data_instruction.reg_data.reg1;
    const uint8_t r_len = instr.data_instruction.reg_data.reg2;

    const uint64_t vm_addr = vm->registers.regs[r_addr].qword();
    const uint64_t len = vm->registers.regs[r_len].qword();

    // Leer el mensaje desde la VM mem a un buffer de pila.  Truncar a
    // 255 bytes (la copia interna en throw_fatal lo trunca a 256
    // incluyendo nul).  Si len = 0 usamos un mensaje por defecto.
    char buf[256];
    if (len == 0 || vm_addr == 0) {
        std::strncpy(buf, "panic", sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
    } else {
        const size_t n_copy = (len < 255) ? (size_t)len : 255;
        vm->vm_mem.read_bytes(vm_addr, buf, n_copy);
        buf[n_copy] = '\0';
    }

    throw_fatal(vm, FATAL_USER_ABORT, buf);
}

void throw_fatalf(ProcessVM *vm, uint32_t kind, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) {
        throw_fatal(vm, kind, "<fmt error>");
        return;
    }
    // vsnprintf trunca implicitamente y ya pone nul terminador.
    throw_fatal(vm, kind, buf);
}

} // namespace runtime
