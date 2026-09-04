/**
 * @file vesta_capi.cpp
 * @brief Implementacion de la API C estable (C-ABI) de VestaVM.
 *
 * Expone @c vesta_compile / @c vesta_run / @c vesta_eval / @c vesta_version /
 * @c vesta_free para embeber el compilador + la VM desde cualquier lenguaje
 * via la libreria compartida @c libvesta.
 *
 * Estrategia de reuso (sin reescribir el pipeline):
 *   - Compilar .vx -> .velb: se replica la secuencia que usa el path
 *     @c --vx de @c main.cpp: @c vx::compile_vx_source produce el texto
 *     @c .vel + el IR serializado; se escribe el @c .vel a un fichero
 *     temporal y se invoca @c asm_multi_process::run_worker (que ensambla
 *     + linka) para producir el @c .velb final; se leen sus bytes a memoria
 *     y se borran los temporales.
 *   - Ejecutar .velb: se replica el path @c --run: se construye una
 *     @c runtime::ManageVM, se crea una VM, se carga el bytecode desde
 *     memoria (@c Loader::load_executable con bytes), se hace @c make_ready,
 *     se arranca el scheduler y se espera con la condition variable
 *     @c done_cv.  El valor de retorno de @c main es el registro R0 del
 *     proceso principal.
 *
 * Toda excepcion C++ se captura en la frontera C; nunca se propaga al
 * llamante (que podria no tener manejo de excepciones C++).
 */

#include "capi/vesta.h"

// IMPORTANTE: parsear los tipos Vesta (PrimitiveKind::VOID/CONST/...) ANTES que
// cualquier header que arrastre <windows.h> (los headers del JIT lo hacen via
// VirtualAlloc), porque Windows define VOID/CONST/IN/OUT/... como macros que
// colisionan con los miembros del enum.  Con types.h ya parseado (guardado),
// las macros posteriores son inocuas.
#include "vx/ast.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "assembly/assembly.h"
#include "cli/vsh.h"
#include "ir/ir_emitter.h"
#include "ir/ssa_ir.h"
#include "ir/ssa_ir_serialize.h" // parse_ir_module_cache (vistas asm/JIT)
#include "loader/loader.h"
#include "runtime/exception_runtime.h"
#include "runtime/manager_runtime.h"
#include "runtime/proceso_runtime.h"
#include "runtime/runtime.h"
#include "util/assembler_multiprocess.h"
#include "vx/compiler.h"
#include "vx/diagnostic.h"
#include "vx/incremental.h"    // CAS + claves Merkle + BuildConfig
#include "vx/lexer.h"          // parse para el indice semantico
#include "vx/parser.h"         // set/get_aot_condcomp_target + Parser
#include "vx/semantic_index.h" // build_semantic_index

#include "jit/code_cache.h"      // vista JIT
#include "jit/runtime_entries.h" // vista JIT
#include "jit/vreg_pipeline.h"   // vista asm nativo (AOT)

#include <algorithm>
#include <capstone/capstone.h>
#include <json.hpp>
#include <sqlite3.h>

// Al descargar libvesta (FreeLibrary / dlclose) hay que retirar el handler
// global de access violations que instala la VM (un VEH en Windows): si la DLL
// se desmapea con el handler aun registrado, la cadena de manejadores del SO
// conserva un puntero a codigo muerto y el cierre del proceso (o la siguiente
// excepcion) salta a esa direccion -> segfault.  Este destructor del modulo
// corre en DLL_PROCESS_DETACH (tanto al descargar en caliente como al salir).
#if defined(__GNUC__)
__attribute__((destructor)) static void vesta_dll_on_unload(void) {
    runtime::uninstall_host_av_handler();
}
#endif

namespace {

namespace fs = std::filesystem;

/// Duplica una cadena C++ a un buffer en heap compatible con @c vesta_free
/// (asignado con @c std::malloc).  Devuelve NULL si la asignacion falla.
char *dup_cstr(const std::string &s) {
    // +1 para el terminador NUL.
    char *p = static_cast<char *>(std::malloc(s.size() + 1));
    if (!p) return nullptr;
    std::memcpy(p, s.data(), s.size());
    p[s.size()] = '\0';
    return p;
}

/// Rellena @c out_err (si no es NULL) con una copia en heap del mensaje.
void set_err(char **out_err, const std::string &msg) {
    if (out_err) *out_err = dup_cstr(msg);
}

/// Construye un texto legible con todos los diagnosticos de error.
std::string format_diags(const vx::Diagnostics &diags) {
    std::ostringstream os;
    // Recorrer todos los diagnosticos; mostrar errores y warnings con
    // su localizacion en formato gcc-like (fichero:linea:columna).
    for (const auto &d : diags.all()) {
        const char *lvl = "info";
        if (d.level == vx::DiagLevel::ERR)
            lvl = "error";
        else if (d.level == vx::DiagLevel::WARN)
            lvl = "warning";
        else if (d.level == vx::DiagLevel::NOTE)
            lvl = "note";
        os << d.loc.file() << ":" << d.loc.line << ":" << d.loc.column << ": "
           << lvl << ": " << d.message << "\n";
    }
    return os.str();
}

/// Genera un prefijo de fichero temporal unico dentro del directorio temporal
/// del sistema (p.ej. "C:/Temp/vesta_capi_ab12cd34").  Sin extension.
std::string make_temp_prefix() {
    // Directorio temporal del SO (TMP/TEMP en Windows, /tmp en POSIX).
    fs::path base;
    try {
        base = fs::temp_directory_path();
    } catch (...) {
        // Fallback al directorio actual si el SO no expone uno.
        base = fs::current_path();
    }
    // Sufijo aleatorio para evitar colisiones entre llamadas concurrentes
    // del mismo proceso o procesos distintos.
    std::random_device rd;
    std::uint64_t r = (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
    std::ostringstream name;
    name << "vesta_capi_" << std::hex << r;
    return (base / name.str()).string();
}

/// Lee un fichero binario completo a un vector de bytes.  Devuelve false si
/// no se puede abrir.
bool read_file_bytes(const std::string &path, std::vector<uint8_t> &out) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    out.assign((std::istreambuf_iterator<char>(f)),
               std::istreambuf_iterator<char>());
    return true;
}

/// Borra de forma silenciosa un fichero (no falla si no existe).
void try_remove(const std::string &path) {
    std::error_code ec;
    fs::remove(path, ec);
}

/**
 * @brief Compila fuente Vesta a bytes .velb (logica interna compartida).
 *
 * @param src        Codigo fuente.
 * @param unit_name  Nombre logico del modulo.
 * @param out_bytes  [salida] Bytes del .velb.
 * @param err        [salida] Mensaje de error si retorna false.
 * @return true si exito.
 */
bool compile_to_velb_bytes(const std::string &src, const std::string &unit_name,
                           std::vector<uint8_t> &out_bytes, std::string &err) {
    // 1. Compilar .vx -> texto .vel + IR serializado (reusa el frontend).
    vx::CompileOptions copts;
    copts.module_name = unit_name.empty() ? std::string("main") : unit_name;

    vx::CompileResult cr =
        vx::compile_vx_source(src, copts.module_name + ".vx", copts);

    if (!cr.ok || cr.diagnostics.has_errors()) {
        err = "fallo de compilacion Vesta:\n" + format_diags(cr.diagnostics);
        return false;
    }

    // 2. Escribir el .vel intermedio a un fichero temporal.  run_worker
    //    opera sobre ficheros y produce <prefijo>.velb.
    const std::string prefix = make_temp_prefix();
    const std::string vel_path = prefix + ".vel";
    const std::string velb_path = prefix + ".velb";

    {
        std::ofstream ofs(vel_path);
        if (!ofs.is_open()) {
            err = "no se pudo crear el temporal: " + vel_path;
            return false;
        }
        ofs << cr.vel_text;
    }

    // 3. Ensamblar + linkar .vel -> .velb (saltando el preprocesador, ya que
    //    el .vel no contiene directivas VPP).  Se pasa el IR pre-serializado
    //    para que el .velb v3 lleve la seccion @ir (habilita auto-JIT).
    int rc =
        asm_multi_process::run_worker(vel_path, prefix,
                                      /*skip_preprocessor=*/true,
                                      /*keep_labels=*/false,
                                      /*ir_section_bytes=*/&cr.ir_section_bytes,
                                      /*emit_map=*/false);

    if (rc != 0) {
        try_remove(vel_path);
        try_remove(velb_path);
        err = "fallo al ensamblar/linkar el .vel a .velb (run_worker rc=" +
              std::to_string(rc) + ")";
        return false;
    }

    // 4. Leer los bytes del .velb resultante.
    bool read_ok = read_file_bytes(velb_path, out_bytes);

    // 5. Limpiar temporales (no afecta al resultado si falla el borrado).
    try_remove(vel_path);
    try_remove(velb_path);

    if (!read_ok || out_bytes.empty()) {
        err = "el .velb generado esta vacio o no se pudo leer";
        return false;
    }
    return true;
}

/**
 * @brief Ensambla + linka texto .vel a bytes .velb (logica interna).
 *
 * Replica el path @c --worker: escribe el texto a un temporal, invoca
 * @c run_worker y lee los bytes del @c .velb resultante.
 *
 * @param vel_text   Texto .vel.
 * @param ir_bytes   IR serializado a embeber (NULL si no aplica).
 * @param out_bytes  [salida] Bytes del .velb.
 * @param err        [salida] Mensaje de error si retorna false.
 * @return true si exito.
 */
bool assemble_vel_to_velb(const std::string &vel_text,
                          const std::vector<uint8_t> *ir_bytes,
                          std::vector<uint8_t> &out_bytes, std::string &err) {
    const std::string prefix = make_temp_prefix();
    const std::string vel_path = prefix + ".vel";
    const std::string velb_path = prefix + ".velb";

    {
        std::ofstream ofs(vel_path);
        if (!ofs.is_open()) {
            err = "no se pudo crear el temporal: " + vel_path;
            return false;
        }
        ofs << vel_text;
    }

    // El texto .vel ya esta desazucarado; saltar el preprocesador VPP.
    int rc = asm_multi_process::run_worker(
        vel_path, prefix,
        /*skip_preprocessor=*/true,
        /*keep_labels=*/false,
        /*ir_section_bytes=*/const_cast<std::vector<uint8_t> *>(ir_bytes),
        /*emit_map=*/false);

    if (rc != 0) {
        try_remove(vel_path);
        try_remove(velb_path);
        err = "fallo al ensamblar/linkar el .vel a .velb (run_worker rc=" +
              std::to_string(rc) + ")";
        return false;
    }

    bool read_ok = read_file_bytes(velb_path, out_bytes);
    try_remove(vel_path);
    try_remove(velb_path);

    if (!read_ok || out_bytes.empty()) {
        err = "el .velb generado esta vacio o no se pudo leer";
        return false;
    }
    return true;
}

/**
 * @brief Mapea el nombre de arquitectura al par (cs_arch, cs_mode).
 *
 * @param arch_name Nombre ("X86-32", "X86-64", "ARM", "AArch64").
 * @param arch      [salida] cs_arch resultante.
 * @param mode      [salida] cs_mode resultante.
 * @return true si la arquitectura se reconoce.
 */
bool map_cs_arch(const std::string &arch_name, cs_arch &arch, cs_mode &mode) {
    if (arch_name == "X86-32") {
        arch = CS_ARCH_X86;
        mode = CS_MODE_32;
    } else if (arch_name == "X86-64") {
        arch = CS_ARCH_X86;
        mode = CS_MODE_64;
    } else if (arch_name == "ARM") {
        arch = CS_ARCH_ARM;
        mode = CS_MODE_ARM;
    } else if (arch_name == "AArch64") {
        arch = static_cast<cs_arch>(_CS_ARCH_ARM64);
        mode = CS_MODE_LITTLE_ENDIAN;
    } else {
        return false;
    }
    return true;
}

/**
 * @brief Ejecuta bytes .velb en una VM nueva y recupera R0 (logica interna).
 *
 * @param velb_bytes  Bytes del .velb.
 * @param argv        Argumentos del programa Vesta.
 * @param out_exit    [salida] Valor de R0 del proceso main.
 * @param err         [salida] Mensaje de error si retorna false.
 * @return true si exito.
 */
bool run_velb_bytes(std::vector<uint8_t> velb_bytes,
                    const std::vector<std::string> &argv, int &out_exit,
                    std::string &err) {
    // Construir el manager + una VM con un unico scheduler (suficiente para
    // ejecutar el proceso main; mismo modelo que el path --run por defecto).
    runtime::ManageVM mgr(nullptr, 0);
    runtime::VM *vm = mgr.loader.create_vm_instance(/*num_schedulers=*/1);
    if (!vm) {
        err = "no se pudo crear la instancia de VM";
        return false;
    }

    // Cargar el bytecode desde memoria (sin pasar por disco).
    runtime::ProcessVM *proc =
        mgr.loader.load_executable(*vm, std::move(velb_bytes));
    if (!proc) {
        err = "no se pudo cargar el ejecutable .velb";
        return false;
    }

    // Argumentos del programa (args_count/args_get del lado Vesta).
    if (!argv.empty()) {
        vm->script_args = argv;
    }

    // Poner el proceso principal en READY y arrancar el scheduler.
    vm->make_ready(proc->pid);
    vm->start();

    // Esperar a que la VM termine via la condition variable (sin polling).
    {
        std::unique_lock<std::mutex> lk(vm->done_mtx);
        vm->done_cv.wait(lk, [&] {
            return !vm->vm_running.load(std::memory_order_acquire);
        });
    }

    // Leer el resultado (R0 del proceso principal) ANTES de parar la VM:
    // el puntero proc sigue siendo valido hasta vm->stop().
    out_exit = static_cast<int>(proc->registers.regs[0].qword());

    vm->stop();
    return true;
}

} // namespace

extern "C" {

VESTA_API const char *vesta_version(void) {
    // Cadena estatica: no requiere liberacion por el llamante.
    return "vesta-capi 1.0";
}

VESTA_API int vesta_compile(const char *src, const char *unit_name,
                            unsigned char **out_velb, size_t *out_len,
                            char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_velb) *out_velb = nullptr;
    if (out_len) *out_len = 0;

    if (!src || !out_velb || !out_len) {
        set_err(out_err, "argumentos invalidos (src/out_velb/out_len NULL)");
        return 1;
    }

    try {
        std::vector<uint8_t> bytes;
        std::string err;
        const std::string unit = unit_name ? unit_name : "main";
        if (!compile_to_velb_bytes(src, unit, bytes, err)) {
            set_err(out_err, err);
            return 1;
        }
        // Copiar los bytes a un buffer en heap (malloc) para el llamante.
        unsigned char *buf =
            static_cast<unsigned char *>(std::malloc(bytes.size()));
        if (!buf) {
            set_err(out_err, "sin memoria al copiar el .velb");
            return 1;
        }
        std::memcpy(buf, bytes.data(), bytes.size());
        *out_velb = buf;
        *out_len = bytes.size();
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_compile: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_compile");
        return 2;
    }
}

VESTA_API int vesta_run(const unsigned char *velb, size_t len, int argc,
                        const char *const *argv, int *out_exit,
                        char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_exit) *out_exit = 0;

    if (!velb || len == 0) {
        set_err(out_err, "argumentos invalidos (velb NULL o len 0)");
        return 1;
    }

    try {
        // Convertir el bytecode a vector y los argumentos a strings.
        std::vector<uint8_t> bytes(velb, velb + len);
        std::vector<std::string> args;
        if (argv && argc > 0) {
            args.reserve(static_cast<size_t>(argc));
            for (int i = 0; i < argc; ++i) {
                args.emplace_back(argv[i] ? argv[i] : "");
            }
        }

        int exit_val = 0;
        std::string err;
        if (!run_velb_bytes(std::move(bytes), args, exit_val, err)) {
            set_err(out_err, err);
            return 1;
        }
        if (out_exit) *out_exit = exit_val;
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err, std::string("excepcion en vesta_run: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_run");
        return 2;
    }
}

VESTA_API int vesta_eval(const char *src, const char *unit_name, int *out_exit,
                         char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_exit) *out_exit = 0;

    if (!src) {
        set_err(out_err, "argumentos invalidos (src NULL)");
        return 1;
    }

    try {
        const std::string unit = unit_name ? unit_name : "main";
        std::vector<uint8_t> bytes;
        std::string err;
        if (!compile_to_velb_bytes(src, unit, bytes, err)) {
            set_err(out_err, err);
            return 1;
        }
        int exit_val = 0;
        if (!run_velb_bytes(std::move(bytes), {}, exit_val, err)) {
            set_err(out_err, err);
            return 1;
        }
        if (out_exit) *out_exit = exit_val;
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err, std::string("excepcion en vesta_eval: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_eval");
        return 2;
    }
}

VESTA_API int vesta_compile_to_vel(const char *src, const char *unit_name,
                                   char **out_vel, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_vel) *out_vel = nullptr;
    if (!src || !out_vel) {
        set_err(out_err, "argumentos invalidos (src/out_vel NULL)");
        return 1;
    }
    try {
        vx::CompileOptions copts;
        copts.module_name = unit_name ? unit_name : "main";
        vx::CompileResult cr =
            vx::compile_vx_source(src, copts.module_name + ".vx", copts);
        if (!cr.ok || cr.diagnostics.has_errors()) {
            set_err(out_err, "fallo de compilacion Vesta:\n" +
                                 format_diags(cr.diagnostics));
            return 1;
        }
        *out_vel = dup_cstr(cr.vel_text);
        if (!*out_vel) {
            set_err(out_err, "sin memoria al copiar el .vel");
            return 1;
        }
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_compile_to_vel: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_compile_to_vel");
        return 2;
    }
}

VESTA_API int vesta_compile_to_ir(const char *src, const char *unit_name,
                                  char **out_ir, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_ir) *out_ir = nullptr;
    if (!src || !out_ir) {
        set_err(out_err, "argumentos invalidos (src/out_ir NULL)");
        return 1;
    }
    try {
        vx::CompileOptions copts;
        copts.module_name = unit_name ? unit_name : "main";
        copts.dump_ir = true; // habilita CompileResult::ir_text
        vx::CompileResult cr =
            vx::compile_vx_source(src, copts.module_name + ".vx", copts);
        if (!cr.ok || cr.diagnostics.has_errors()) {
            set_err(out_err, "fallo de compilacion Vesta:\n" +
                                 format_diags(cr.diagnostics));
            return 1;
        }
        *out_ir = dup_cstr(cr.ir_text);
        if (!*out_ir) {
            set_err(out_err, "sin memoria al copiar el IR");
            return 1;
        }
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_compile_to_ir: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_compile_to_ir");
        return 2;
    }
}

VESTA_API int vesta_assemble(const char *vel_text, unsigned char **out_velb,
                             size_t *out_len, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_velb) *out_velb = nullptr;
    if (out_len) *out_len = 0;
    if (!vel_text || !out_velb || !out_len) {
        set_err(out_err,
                "argumentos invalidos (vel_text/out_velb/out_len NULL)");
        return 1;
    }
    try {
        std::vector<uint8_t> bytes;
        std::string err;
        if (!assemble_vel_to_velb(vel_text, /*ir_bytes=*/nullptr, bytes, err)) {
            set_err(out_err, err);
            return 1;
        }
        unsigned char *buf =
            static_cast<unsigned char *>(std::malloc(bytes.size()));
        if (!buf) {
            set_err(out_err, "sin memoria al copiar el .velb");
            return 1;
        }
        std::memcpy(buf, bytes.data(), bytes.size());
        *out_velb = buf;
        *out_len = bytes.size();
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_assemble: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_assemble");
        return 2;
    }
}

VESTA_API int vesta_disasm(const unsigned char *bytes, size_t len,
                           const char *arch, char **out_text, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_text) *out_text = nullptr;
    if (!bytes || len == 0 || !out_text) {
        set_err(out_err, "argumentos invalidos (bytes/len/out_text)");
        return 1;
    }
    try {
        const std::string arch_name = arch ? arch : "X86-64";
        cs_arch cs_a;
        cs_mode cs_m;
        if (!map_cs_arch(arch_name, cs_a, cs_m)) {
            set_err(out_err, "arquitectura desconocida: " + arch_name);
            return 1;
        }
        csh handle;
        if (cs_open(cs_a, cs_m, &handle) != CS_ERR_OK) {
            set_err(out_err, "error inicializando Capstone para " + arch_name);
            return 1;
        }
        cs_insn *insn = nullptr;
        // 0x1000 = direccion virtual base asumida (igual que disassemble_file).
        size_t count = cs_disasm(handle, bytes, len, 0x1000, 0, &insn);
        if (count == 0) {
            cs_close(&handle);
            set_err(out_err, "no se pudo desensamblar el buffer");
            return 1;
        }
        std::ostringstream os;
        for (size_t i = 0; i < count; ++i) {
            os << "0x" << std::hex << insn[i].address << ":\t"
               << insn[i].mnemonic << "\t" << insn[i].op_str << "\n";
        }
        cs_free(insn, count);
        cs_close(&handle);
        *out_text = dup_cstr(os.str());
        if (!*out_text) {
            set_err(out_err, "sin memoria al copiar el desensamblado");
            return 1;
        }
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err, std::string("excepcion en vesta_disasm: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_disasm");
        return 2;
    }
}

VESTA_API int vesta_diagram(const char *src, const char *unit_name,
                            const char *kind, const char *format,
                            char **out_text, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_text) *out_text = nullptr;
    if (!src || !kind || !format || !out_text) {
        set_err(out_err, "argumentos invalidos (src/kind/format/out_text)");
        return 1;
    }
    try {
        const std::string k = kind;
        const std::string f = format;
        if (k != "ast" && k != "ir-pre" && k != "ir-post" && k != "vel") {
            set_err(out_err,
                    "kind desconocido: " + k + " (usa ast|ir-pre|ir-post|vel)");
            return 1;
        }
        if (f != "mermaid" && f != "graphviz" && f != "html") {
            set_err(out_err, "format desconocido: " + f +
                                 " (usa mermaid|graphviz|html)");
            return 1;
        }

        vx::CompileOptions copts;
        copts.module_name = unit_name ? unit_name : "main";
        // Activar solo el flag de la vista + formato pedidos.
        const bool ast = (k == "ast");
        const bool ir_pre = (k == "ir-pre");
        const bool ir_post = (k == "ir-post");
        const bool vel = (k == "vel");
        if (f == "mermaid") {
            copts.dump_mermaid_ast = ast;
            copts.dump_mermaid_ir_pre = ir_pre;
            copts.dump_mermaid_ir_post = ir_post;
            copts.dump_mermaid_vel = vel;
        } else if (f == "graphviz") {
            copts.dump_graphviz_ast = ast;
            copts.dump_graphviz_ir_pre = ir_pre;
            copts.dump_graphviz_ir_post = ir_post;
            copts.dump_graphviz_vel = vel;
        } else { // html
            copts.dump_html_ast = ast;
            copts.dump_html_ir_pre = ir_pre;
            copts.dump_html_ir_post = ir_post;
            copts.dump_html_vel = vel;
        }

        vx::CompileResult cr =
            vx::compile_vx_source(src, copts.module_name + ".vx", copts);
        if (!cr.ok || cr.diagnostics.has_errors()) {
            set_err(out_err, "fallo de compilacion Vesta:\n" +
                                 format_diags(cr.diagnostics));
            return 1;
        }

        // Seleccionar el campo del CompileResult correspondiente.
        const std::string *sel = nullptr;
        if (f == "mermaid") {
            sel = ast       ? &cr.mermaid_ast
                  : ir_pre  ? &cr.mermaid_ir_pre
                  : ir_post ? &cr.mermaid_ir_post
                            : &cr.mermaid_vel;
        } else if (f == "graphviz") {
            sel = ast       ? &cr.graphviz_ast
                  : ir_pre  ? &cr.graphviz_ir_pre
                  : ir_post ? &cr.graphviz_ir_post
                            : &cr.graphviz_vel;
        } else {
            sel = ast       ? &cr.html_ast
                  : ir_pre  ? &cr.html_ir_pre
                  : ir_post ? &cr.html_ir_post
                            : &cr.html_vel;
        }
        if (!sel || sel->empty()) {
            set_err(out_err, "diagrama vacio para kind=" + k + " format=" + f);
            return 1;
        }
        *out_text = dup_cstr(*sel);
        if (!*out_text) {
            set_err(out_err, "sin memoria al copiar el diagrama");
            return 1;
        }
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_diagram: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_diagram");
        return 2;
    }
}

// ------------------------------------------------------------------------- //
// Vistas por OS/arquitectura (VestaTarget).                                 //
// ------------------------------------------------------------------------- //
namespace {

/// Normaliza el nombre de arch del C-API al que espera el parser / codegen.
std::string vt_norm_arch_(const char *a) {
    if (!a || !*a) return "x86_64";
    std::string s = a;
    if (s == "x86-64" || s == "x86_64" || s == "x64" || s == "amd64")
        return "x86_64";
    if (s == "x86-32" || s == "x86_32" || s == "x86" || s == "i386")
        return "x86";
    if (s == "arm64" || s == "aarch64") return "arm64";
    return s;
}

/// Normaliza el nombre de OS ("" = host, sin override).
std::string vt_norm_os_(const char *o) {
    if (!o || !*o) return std::string();
    return std::string(o);
}

/// Deriva el formato de objeto ("pe"/"elf") a partir del target.
std::string vt_fmt_(const VestaTarget *t) {
    if (t && t->fmt && *t->fmt) return std::string(t->fmt);
    const std::string os = t ? vt_norm_os_(t->os) : std::string();
    if (os == "windows") return "pe";
    if (os == "linux" || os == "macos") return "elf";
#if defined(_WIN32)
    return "pe";
#else
    return "elf";
#endif
}

/// RAII: aplica el override de @Target del target y lo restaura al destruir.
/// Sin target (o target == host x86-64) no toca el thread_local del parser.
struct TargetGuard {
    std::string prev_os, prev_arch;
    bool active = false;
    explicit TargetGuard(const VestaTarget *t) {
        if (!t) return;
        std::string os = vt_norm_os_(t->os);
        std::string arch = vt_norm_arch_(t->arch);
        // Solo activar si hay un override real (os no-host o arch != default).
        if (os.empty() && arch == "x86_64") return;
        vx::get_aot_condcomp_target(prev_os, prev_arch);
        vx::set_aot_condcomp_target(os, arch);
        active = true;
    }
    ~TargetGuard() {
        if (active) vx::set_aot_condcomp_target(prev_os, prev_arch);
    }
    TargetGuard(const TargetGuard &) = delete;
    TargetGuard &operator=(const TargetGuard &) = delete;
};

/// Rellena @c copts con el target: native_poo + bits del arch.
void vt_apply_opts_(const VestaTarget *t, vx::CompileOptions &copts) {
    if (!t) return;
    if (t->native_poo) copts.native_poo = true;
}

/// Desensambla un buffer de bytes nativos a texto (Capstone).  @p mode32
/// elige x86-32 vs x86-64.  Devuelve "" si falla (el llamante anota el fallo).
std::string vt_disasm_(const std::vector<uint8_t> &bytes, bool mode32) {
    if (bytes.empty()) return std::string();
    cs_arch a = CS_ARCH_X86;
    cs_mode m = mode32 ? CS_MODE_32 : CS_MODE_64;
    csh h;
    if (cs_open(a, m, &h) != CS_ERR_OK) return std::string();
    cs_insn *insn = nullptr;
    const size_t n = cs_disasm(h, bytes.data(), bytes.size(), 0x0, 0, &insn);
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        char line[128];
        std::snprintf(line, sizeof(line), "  %04llx  %-9s %s\n",
                      static_cast<unsigned long long>(insn[i].address),
                      insn[i].mnemonic, insn[i].op_str);
        out += line;
    }
    if (insn) cs_free(insn, n);
    cs_close(&h);
    return out;
}

} // namespace

VESTA_API int vesta_compile_to_ir_t(const char *src, const char *unit_name,
                                    const VestaTarget *target, char **out_ir,
                                    char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_ir) *out_ir = nullptr;
    if (!src || !out_ir) {
        set_err(out_err, "argumentos invalidos (src/out_ir NULL)");
        return 1;
    }
    try {
        TargetGuard guard(target);
        vx::CompileOptions copts;
        copts.module_name = unit_name ? unit_name : "main";
        copts.dump_ir = true;
        vt_apply_opts_(target, copts);
        vx::CompileResult cr =
            vx::compile_vx_source(src, copts.module_name + ".vx", copts);
        if (!cr.ok || cr.diagnostics.has_errors()) {
            set_err(out_err, "fallo de compilacion Vesta:\n" +
                                 format_diags(cr.diagnostics));
            return 1;
        }
        *out_ir = dup_cstr(cr.ir_text);
        if (!*out_ir) {
            set_err(out_err, "sin memoria al copiar el IR");
            return 1;
        }
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_compile_to_ir_t: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_compile_to_ir_t");
        return 2;
    }
}

VESTA_API int vesta_compile_to_vel_t(const char *src, const char *unit_name,
                                     const VestaTarget *target, char **out_vel,
                                     char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_vel) *out_vel = nullptr;
    if (!src || !out_vel) {
        set_err(out_err, "argumentos invalidos (src/out_vel NULL)");
        return 1;
    }
    try {
        TargetGuard guard(target);
        vx::CompileOptions copts;
        copts.module_name = unit_name ? unit_name : "main";
        vt_apply_opts_(target, copts);
        vx::CompileResult cr =
            vx::compile_vx_source(src, copts.module_name + ".vx", copts);
        if (!cr.ok || cr.diagnostics.has_errors()) {
            set_err(out_err, "fallo de compilacion Vesta:\n" +
                                 format_diags(cr.diagnostics));
            return 1;
        }
        *out_vel = dup_cstr(cr.vel_text);
        if (!*out_vel) {
            set_err(out_err, "sin memoria al copiar el .vel");
            return 1;
        }
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err, std::string("excepcion en vesta_compile_to_vel_t: ") +
                             e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_compile_to_vel_t");
        return 2;
    }
}

VESTA_API int vesta_diagram_t(const char *src, const char *unit_name,
                              const char *kind, const char *format,
                              const VestaTarget *target, char **out_text,
                              char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_text) *out_text = nullptr;
    if (!src || !kind || !format || !out_text) {
        set_err(out_err, "argumentos invalidos (src/kind/format/out_text)");
        return 1;
    }
    // La vista "asm" del diagrama se delega a la vista de asm nativo (texto
    // plano por ahora; el front-end puede envolverlo).  El resto reusa el
    // pipeline de diagramas con el target aplicado.
    {
        TargetGuard guard(target);
        return vesta_diagram(src, unit_name, kind, format, out_text, out_err);
    }
}

VESTA_API int vesta_compile_to_asm_t(const char *src, const char *unit_name,
                                     const VestaTarget *target, char **out_asm,
                                     char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_asm) *out_asm = nullptr;
    if (!src || !out_asm) {
        set_err(out_err, "argumentos invalidos (src/out_asm NULL)");
        return 1;
    }
    try {
        TargetGuard guard(target);
        const std::string fmt = vt_fmt_(target);
        const bool sysv = (fmt == "elf");
        const std::string arch = vt_norm_arch_(target ? target->arch : nullptr);
        const bool mode32 = (arch == "x86");

        vx::CompileOptions copts;
        copts.module_name = unit_name ? unit_name : "main";
        copts.native_poo = true; // la vista asm nativa requiere el lowering AOT
        vx::CompileResult cr =
            vx::compile_vx_source(src, copts.module_name + ".vx", copts);
        if (!cr.ok || cr.diagnostics.has_errors()) {
            set_err(out_err, "fallo de compilacion Vesta:\n" +
                                 format_diags(cr.diagnostics));
            return 1;
        }
        ir::IrModule mod;
        if (cr.ir_module_cache_bytes.empty() ||
            !ir::parse_ir_module_cache(cr.ir_module_cache_bytes, mod)) {
            set_err(out_err, "no se pudo obtener el IR del modulo para el asm");
            return 1;
        }
        std::string out;
        out += "; asm nativo AOT  target=" +
               (target && target->os && *target->os ? std::string(target->os)
                                                    : std::string("host")) +
               " " + arch + " " + fmt + "\n";
        for (const auto &fn : mod.functions) {
            std::vector<jit::NativeReloc> relocs;
            std::vector<uint8_t> bytes = jit::vreg_compile_native(
                fn, {}, {}, {}, {}, &relocs, /*pic=*/false,
                /*target_sysv=*/sysv, /*mode32=*/mode32, jit::FloatIsa::SSE2);
            out += "\n; === " + fn.name + " ===\n";
            if (bytes.empty()) {
                out +=
                    "; (op fuera del subset nativo -> no compilable a asm)\n";
                continue;
            }
            const std::string dis = vt_disasm_(bytes, mode32);
            out += dis.empty() ? "; (desensamblado vacio)\n" : dis;
        }
        *out_asm = dup_cstr(out);
        if (!*out_asm) {
            set_err(out_err, "sin memoria al copiar el asm");
            return 1;
        }
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err, std::string("excepcion en vesta_compile_to_asm_t: ") +
                             e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_compile_to_asm_t");
        return 2;
    }
}

VESTA_API int vesta_compile_to_jit_t(const char *src, const char *unit_name,
                                     const VestaTarget *target, char **out_asm,
                                     char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_asm) *out_asm = nullptr;
    if (!src || !out_asm) {
        set_err(out_err, "argumentos invalidos (src/out_asm NULL)");
        return 1;
    }
    try {
        // El JIT es x86-64 host; el @c os solo afecta las ramas @Target.
        TargetGuard guard(target);
        vx::CompileOptions copts;
        copts.module_name = unit_name ? unit_name : "main";
        vx::CompileResult cr =
            vx::compile_vx_source(src, copts.module_name + ".vx", copts);
        if (!cr.ok || cr.diagnostics.has_errors()) {
            set_err(out_err, "fallo de compilacion Vesta:\n" +
                                 format_diags(cr.diagnostics));
            return 1;
        }
        ir::IrModule mod;
        if (cr.ir_module_cache_bytes.empty() ||
            !ir::parse_ir_module_cache(cr.ir_module_cache_bytes, mod)) {
            set_err(out_err, "no se pudo obtener el IR del modulo para el JIT");
            return 1;
        }
        /* La vista la produce el MISMO camino que el JIT de verdad -- el de
         * registros virtuales --, igual que hace el inspector del editor.
         * Antes decia "vreg" en la cabecera y en el mensaje de operacion no
         * soportada, pero compilaba con el selector de huecos de pila, que
         * estaba jubilado: se ensenaba codigo de un backend que ya no ejecuta
         * nada.  Se compila cada funcion AISLADA (sin resolver las llamadas a
         * otras) porque esto solo se lee, no se ejecuta. */
        std::string out;
        out += "; asm JIT (vreg, x86-64 host)\n";
        for (const auto &fn : mod.functions) {
            out += "\n; === " + fn.name + " ===\n";
            std::vector<uint8_t> bytes;
            try {
                bytes = jit::vreg_compile_native(fn);
            } catch (...) {
                out += "; (el codegen lanzo una excepcion)\n";
                continue;
            }
            if (bytes.empty()) {
                out += "; (operacion no soportada por el JIT)\n";
                continue;
            }
            const std::string dis = vt_disasm_(bytes, /*mode32=*/false);
            out += dis.empty() ? "; (desensamblado vacio)\n" : dis;
        }
        *out_asm = dup_cstr(out);
        if (!*out_asm) {
            set_err(out_err, "sin memoria al copiar el asm JIT");
            return 1;
        }
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err, std::string("excepcion en vesta_compile_to_jit_t: ") +
                             e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_compile_to_jit_t");
        return 2;
    }
}

VESTA_API int vesta_vsh_eval(const char *script, int *out_rc, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_rc) *out_rc = 0;
    if (!script) {
        set_err(out_err, "argumentos invalidos (script NULL)");
        return 1;
    }
    try {
        vsh::VshInterpreter interp;
        std::vector<std::string> argv = {"<capi>"};
        interp.set_argv(argv);
        interp.exec_string(script, "<capi>");
        if (out_rc) *out_rc = 0;
        return 0;
    } catch (const vsh::VshRuntimeError &e) {
        std::ostringstream os;
        os << "VSH runtime error";
        if (e.line > 0) os << " (linea " << e.line << ")";
        os << ": " << e.what();
        set_err(out_err, os.str());
        if (out_rc) *out_rc = 1;
        return 1;
    } catch (const vsh::VshParseError &e) {
        std::ostringstream os;
        os << "VSH parse error";
        if (e.line > 0) os << " (linea " << e.line << ")";
        os << ": " << e.what();
        set_err(out_err, os.str());
        if (out_rc) *out_rc = 1;
        return 1;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_vsh_eval: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_vsh_eval");
        return 2;
    }
}

VESTA_API int vesta_compile_full(const char *src, const char *unit_name,
                                 char **out_vel, char **out_ir,
                                 unsigned char **out_velb, size_t *out_velb_len,
                                 char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_vel) *out_vel = nullptr;
    if (out_ir) *out_ir = nullptr;
    if (out_velb) *out_velb = nullptr;
    if (out_velb_len) *out_velb_len = 0;
    if (!src) {
        set_err(out_err, "argumentos invalidos (src NULL)");
        return 1;
    }
    if (out_velb && !out_velb_len) {
        set_err(out_err, "out_velb requiere out_velb_len");
        return 1;
    }
    try {
        // Compilar una sola vez activando dump_ir.
        vx::CompileOptions copts;
        copts.module_name = unit_name ? unit_name : "main";
        copts.dump_ir = (out_ir != nullptr);
        vx::CompileResult cr =
            vx::compile_vx_source(src, copts.module_name + ".vx", copts);
        if (!cr.ok || cr.diagnostics.has_errors()) {
            set_err(out_err, "fallo de compilacion Vesta:\n" +
                                 format_diags(cr.diagnostics));
            return 1;
        }

        if (out_vel) {
            *out_vel = dup_cstr(cr.vel_text);
            if (!*out_vel) {
                set_err(out_err, "sin memoria al copiar el .vel");
                return 1;
            }
        }
        if (out_ir) {
            *out_ir = dup_cstr(cr.ir_text);
            if (!*out_ir) {
                set_err(out_err, "sin memoria al copiar el IR");
                return 1;
            }
        }
        if (out_velb) {
            std::vector<uint8_t> bytes;
            std::string err;
            // Embeber el IR para producir un .velb v3 igual que vesta_compile.
            if (!assemble_vel_to_velb(cr.vel_text, &cr.ir_section_bytes, bytes,
                                      err)) {
                set_err(out_err, err);
                return 1;
            }
            unsigned char *buf =
                static_cast<unsigned char *>(std::malloc(bytes.size()));
            if (!buf) {
                set_err(out_err, "sin memoria al copiar el .velb");
                return 1;
            }
            std::memcpy(buf, bytes.data(), bytes.size());
            *out_velb = buf;
            *out_velb_len = bytes.size();
        }
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_compile_full: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_compile_full");
        return 2;
    }
}

VESTA_API int vesta_ir_to_velb(const char *ir_text, unsigned char **out_velb,
                               size_t *out_len, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_velb) *out_velb = nullptr;
    if (out_len) *out_len = 0;
    if (!ir_text || !out_velb || !out_len) {
        set_err(out_err,
                "argumentos invalidos (ir_text/out_velb/out_len NULL)");
        return 1;
    }
    try {
        // 1. Parsear el texto IR SSA a un IrModule.
        ir::IrModule mod;
        std::string parse_err;
        if (!ir::ir_parse(ir_text, mod, parse_err)) {
            set_err(out_err, "fallo al parsear el IR: " + parse_err);
            return 1;
        }

        // 2. Emitir el texto .vel desde el IR (aplica optimizacion + regalloc).
        ir::EmitResult er = ir::ir_emit_module(mod);
        if (!er.ok) {
            set_err(out_err,
                    "fallo al emitir el .vel desde el IR: " + er.error);
            return 1;
        }

        // 3. Ensamblar + linkar el .vel a .velb (mismo path que
        // vesta_assemble).
        std::vector<uint8_t> bytes;
        std::string err;
        if (!assemble_vel_to_velb(er.vel_text, /*ir_bytes=*/nullptr, bytes,
                                  err)) {
            set_err(out_err, err);
            return 1;
        }

        // 4. Copiar los bytes a un buffer en heap (malloc) para el llamante.
        unsigned char *buf =
            static_cast<unsigned char *>(std::malloc(bytes.size()));
        if (!buf) {
            set_err(out_err, "sin memoria al copiar el .velb");
            return 1;
        }
        std::memcpy(buf, bytes.data(), bytes.size());
        *out_velb = buf;
        *out_len = bytes.size();
        return 0;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_ir_to_velb: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_ir_to_velb");
        return 2;
    }
}

VESTA_API int vesta_json_validate(const char *json_text, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (!json_text) {
        set_err(out_err, "argumentos invalidos (json_text NULL)");
        return 1;
    }
    try {
        // Parsear sin callback de errores => lanza nlohmann::json::parse_error.
        nlohmann::json parsed = nlohmann::json::parse(json_text);
        (void)parsed;
        return 0;
    } catch (const nlohmann::json::parse_error &e) {
        set_err(out_err, std::string("JSON invalido: ") + e.what());
        return 1;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_json_validate: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_json_validate");
        return 2;
    }
}

VESTA_API int vesta_json_format(const char *json_text, int indent,
                                char **out_text, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_text) *out_text = nullptr;
    if (!json_text || !out_text) {
        set_err(out_err, "argumentos invalidos (json_text/out_text NULL)");
        return 1;
    }
    try {
        nlohmann::json j = nlohmann::json::parse(json_text);
        // indent < 0 => compacto (dump sin sangria); >= 0 => pretty.
        std::string formatted = (indent < 0) ? j.dump() : j.dump(indent);
        *out_text = dup_cstr(formatted);
        if (!*out_text) {
            set_err(out_err, "sin memoria al copiar el JSON formateado");
            return 1;
        }
        return 0;
    } catch (const nlohmann::json::parse_error &e) {
        set_err(out_err, std::string("JSON invalido: ") + e.what());
        return 1;
    } catch (const std::exception &e) {
        set_err(out_err,
                std::string("excepcion en vesta_json_format: ") + e.what());
        return 2;
    } catch (...) {
        set_err(out_err, "excepcion desconocida en vesta_json_format");
        return 2;
    }
}

VESTA_API int vesta_sqlite_exec(const char *db_path, const char *sql,
                                char **out_json, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (out_json) *out_json = nullptr;
    if (!db_path || !sql || !out_json) {
        set_err(out_err, "argumentos invalidos (db_path/sql/out_json NULL)");
        return 1;
    }

    sqlite3 *db = nullptr;
    try {
        // Abrir la BD (acepta ":memory:" para una BD en memoria).
        if (sqlite3_open(db_path, &db) != SQLITE_OK) {
            std::string msg = "no se pudo abrir la BD: ";
            msg += db ? sqlite3_errmsg(db) : "error desconocido";
            set_err(out_err, msg);
            if (db) sqlite3_close(db);
            return 1;
        }

        // Acumulador de las filas del/los SELECT como array de objetos JSON.
        nlohmann::json rows = nlohmann::json::array();

        // Recorrer todas las sentencias del bloque SQL con
        // prepare/step/finalize.
        const char *cursor = sql;
        while (cursor && *cursor) {
            sqlite3_stmt *stmt = nullptr;
            const char *tail = nullptr;
            int rc = sqlite3_prepare_v2(db, cursor, -1, &stmt, &tail);
            if (rc != SQLITE_OK) {
                std::string msg = "error de prepare: ";
                msg += sqlite3_errmsg(db);
                set_err(out_err, msg);
                if (stmt) sqlite3_finalize(stmt);
                sqlite3_close(db);
                return 1;
            }
            // prepare puede devolver stmt NULL si el segmento era solo espacios
            // o un comentario; avanzar al siguiente segmento.
            if (!stmt) {
                cursor = tail;
                continue;
            }

            const int ncols = sqlite3_column_count(stmt);
            // Ejecutar la sentencia, recolectando filas si las produce.
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                nlohmann::json obj = nlohmann::json::object();
                for (int c = 0; c < ncols; ++c) {
                    const char *cname = sqlite3_column_name(stmt, c);
                    const std::string key =
                        cname ? cname : ("col" + std::to_string(c));
                    // Mapear el tipo nativo de SQLite al tipo JSON adecuado.
                    switch (sqlite3_column_type(stmt, c)) {
                    case SQLITE_INTEGER:
                        obj[key] = static_cast<std::int64_t>(
                            sqlite3_column_int64(stmt, c));
                        break;
                    case SQLITE_FLOAT:
                        obj[key] = sqlite3_column_double(stmt, c);
                        break;
                    case SQLITE_NULL: obj[key] = nullptr; break;
                    case SQLITE_BLOB: {
                        // Representar el blob como su longitud en bytes; el
                        // contenido binario crudo no es JSON-serializable.
                        int n = sqlite3_column_bytes(stmt, c);
                        obj[key] = std::string("<blob ") + std::to_string(n) +
                                   " bytes>";
                        break;
                    }
                    case SQLITE_TEXT:
                    default: {
                        const unsigned char *txt = sqlite3_column_text(stmt, c);
                        obj[key] =
                            txt ? reinterpret_cast<const char *>(txt) : "";
                        break;
                    }
                    }
                }
                rows.push_back(std::move(obj));
            }
            if (rc != SQLITE_DONE) {
                std::string msg = "error de step: ";
                msg += sqlite3_errmsg(db);
                set_err(out_err, msg);
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                return 1;
            }
            sqlite3_finalize(stmt);
            cursor = tail;
        }

        sqlite3_close(db);
        db = nullptr;

        *out_json = dup_cstr(rows.dump());
        if (!*out_json) {
            set_err(out_err, "sin memoria al copiar el JSON de filas");
            return 1;
        }
        return 0;
    } catch (const std::exception &e) {
        if (db) sqlite3_close(db);
        set_err(out_err,
                std::string("excepcion en vesta_sqlite_exec: ") + e.what());
        return 2;
    } catch (...) {
        if (db) sqlite3_close(db);
        set_err(out_err, "excepcion desconocida en vesta_sqlite_exec");
        return 2;
    }
}

/* -- Compilacion incremental / CAS ------------------------------------- */

VESTA_API int vesta_build_fingerprint(const VestaBuildConfig *cfg,
                                      unsigned long long *out_ir_fp,
                                      unsigned long long *out_full_fp) {
    if (!cfg || !out_ir_fp || !out_full_fp) return 1;
    try {
        vx::BuildConfig b;
        b.asm_target_bits = cfg->asm_target_bits ? cfg->asm_target_bits : 64;
        b.native_poo = cfg->native_poo != 0;
        b.exceptions_enabled = cfg->exceptions_enabled != 0;
        b.instrument_mode = cfg->instrument_mode ? cfg->instrument_mode : "";
        b.tgt_os = cfg->tgt_os ? cfg->tgt_os : "";
        b.tgt_arch = cfg->tgt_arch ? cfg->tgt_arch : "";
        b.opt_level = cfg->opt_level;
        b.emit_debug = cfg->emit_debug != 0;
        b.aot_vec_width = cfg->aot_vec_width ? cfg->aot_vec_width : 16;
        b.profile_id = cfg->profile_id ? cfg->profile_id : "";
        *out_ir_fp = b.ir_fingerprint();
        *out_full_fp = b.full_fingerprint();
        return 0;
    } catch (...) {
        return 2;
    }
}

/// Handle opaco: envuelve un @c vx::CasStore por valor.
struct VestaCas {
    vx::CasStore store;
};

VESTA_API VestaCas *vesta_cas_open(const char *dir) {
    try {
        if (dir && *dir) return new VestaCas{vx::CasStore(std::string(dir))};
        return new VestaCas{vx::CasStore::open_default()};
    } catch (...) {
        return nullptr;
    }
}

VESTA_API void vesta_cas_close(VestaCas *cas) {
    delete cas;
}

VESTA_API int vesta_cas_has(VestaCas *cas, unsigned long long key) {
    if (!cas) return 0;
    return cas->store.has(static_cast<vx::MerkleKey>(key)) ? 1 : 0;
}

VESTA_API int vesta_cas_get(VestaCas *cas, unsigned long long key,
                            unsigned char **out_data, size_t *out_len) {
    if (out_data) *out_data = nullptr;
    if (out_len) *out_len = 0;
    if (!cas || !out_data || !out_len) return 1;
    try {
        std::vector<uint8_t> buf;
        if (!cas->store.get(static_cast<vx::MerkleKey>(key), buf)) return 2;
        unsigned char *p = static_cast<unsigned char *>(
            std::malloc(buf.empty() ? 1 : buf.size()));
        if (!p) return 3;
        if (!buf.empty()) std::memcpy(p, buf.data(), buf.size());
        *out_data = p;
        *out_len = buf.size();
        return 0;
    } catch (...) {
        return 4;
    }
}

VESTA_API int vesta_cas_put(VestaCas *cas, unsigned long long key,
                            const unsigned char *data, size_t len) {
    if (!cas || (len > 0 && !data)) return 1;
    try {
        return cas->store.put(static_cast<vx::MerkleKey>(key), data, len) ? 0
                                                                          : 2;
    } catch (...) {
        return 3;
    }
}

VESTA_API int vesta_merkle_keys_json(const char *src, const char *unit_name,
                                     char **out_json) {
    if (out_json) *out_json = nullptr;
    if (!src || !out_json) return 1;
    try {
        const std::string uni = unit_name ? unit_name : "main";
        vx::Diagnostics diag;
        vx::Lexer lx(src, uni + ".vx", diag);
        vx::Parser sp(lx, diag);
        auto mod = sp.parse_program();
        if (!mod) return 2;
        vx::SemanticIndex idx = vx::build_semantic_index(*mod, src, uni);
        vx::MerkleKeys keys = vx::compute_merkle_keys(idx);

        auto esc = [](const std::string &s) {
            std::string o;
            for (char c : s) {
                if (c == '"' || c == '\\') {
                    o.push_back('\\');
                    o.push_back(c);
                } else if (c == '\n') {
                    o += "\\n";
                } else {
                    o.push_back(c);
                }
            }
            return o;
        };
        auto hex64 = [](uint64_t v) {
            char b[19];
            std::snprintf(b, sizeof(b), "0x%016llx",
                          static_cast<unsigned long long>(v));
            return std::string(b);
        };

        std::ostringstream j;
        j << "{\"module\":\"" << esc(idx.module_path) << "\",\"symbols\":[";
        for (size_t i = 0; i < idx.symbols.size(); ++i) {
            const auto &s = idx.symbols[i];
            if (i) j << ",";
            j << "{\"name\":\"" << esc(s.name)
              << "\",\"kind\":" << static_cast<unsigned>(s.kind)
              << ",\"content_hash\":\"" << hex64(s.content_hash)
              << "\",\"merkle_key\":\"" << hex64(keys.of(s.name))
              << "\",\"is_public\":" << (s.is_public ? "true" : "false")
              << ",\"deps\":[";
            for (size_t k = 0; k < s.deps.size(); ++k) {
                if (k) j << ",";
                j << "\"" << esc(s.deps[k]) << "\"";
            }
            j << "]}";
        }
        j << "]}";
        *out_json = dup_cstr(j.str());
        return *out_json ? 0 : 3;
    } catch (...) {
        return 4;
    }
}

VESTA_API void vesta_free(void *p) {
    // Aceptar NULL es seguro.  Los buffers se asignaron con malloc.
    if (p) std::free(p);
}

} // extern "C"
