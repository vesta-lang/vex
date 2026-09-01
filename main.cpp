/*
 * VestaVM - Máquina Virtual Distribuida
 *
 * Copyright © 2026 David López.T (DesmonHak) (Castilla y León, ES)
 * Licencia VMProject
 *
 * USO LIBRE NO COMERCIAL con atribución obligatoria.
 * PROHIBIDO lucro sin permiso escrito.
 *
 * Descargo: Autor no responsable por modificaciones.
 */

#include "util/env_flags.h"
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <fstream>

#include "disasm/disasm.h"
#include "vx/fmt/fmt.h"
#include "vx/fmt/fmt_cli.h"
#include "vx/fmt/fmt_driver.h"
#include <sstream>
#include <thread>
#include <atomic>
#include <csignal>
#include <openssl/sha.h>

#include "cxxopts.hpp"

#include "cli/cli.h"
#include "cli/vsh.h"
#include "cli/version_info.h"   // Banner de `vesta --version` / `-v`
#include "analysis/asa/dump.h"  // Volcado del ASA: modo --asa
#include "analyze/asm_report.h" // Informe de bloques asm + su productor del ASA
#include "analyze/lint_cli.h"   // Subcomando `vesta lint`
#include "analyze/bigo.h"       // Subsistema de coste: modo --analyze (Big-O)
#include "analyze/fingerprint.h" // Huella computacional (recursos + efectos)
#include "analysis/effects/effects_report.h" // Modelo unico de efectos: --analyze --effects
#include "vx/contract_when.h" // registro de arquitecturas conocidas
#include "ir/ir_emitter.h"
#include "ir/passes/select_policy.h" // PGO: load_branch_profile (if-conversion)
#include "ir/ssa_ir_serialize.h" //  AOT: parse_ir_section (round-trip del @ir)
#include "aot/aot_analyze.h"     //  analisis de compatibilidad nativa
#include "aot/aot_lower.h"       //  re-bajada RAW_ALLOC/FREE/PANIC -> CALL
#include "aot/object_writer.h"   //  AOT.4: emisor PE/ELF (ObjectWriter)
#include "aot/aot_native.h"      //   _start arch-portable
#include "aot/linker.h"          //  linker propio (enlaza .o)
#include "jit/vreg_pipeline.h"   //   vreg_compile_native (HOST_LEAF)
#include "jit/vec_isa.h"         // ancho SIMD del target (--float-isa)
#include "jit/backend_caps.h"    // caps del target para el gate FMA (AOT)
#include "jit/auto_jit.h"
#include "jit/jit_timing.h"
#include "jit/jit_branch_prof.h"
#include "jit/sched/cost_model.h" // --cpu: microarquitectura objetivo del scheduler
#include "jit/keystone_asm_backend.h"  //  registrar backend asm
#include "jit/inline_asm_trampoline.h" //  helper runner inline-asm
#include "jit/naked_native.h" // Bug 198: dispatcher naked (asm con simbolos propios)
#include "runtime/profile.h" //
#include "pkg/cli.h"
#include "runtime/proceso_runtime.h"
#include "cli/runtime_api_commands.h"
#include "toolchain/aot_build.h" // AOT nativo extraido (vesta::tc::compile_aot)
#include "util/assembler_multiprocess.h"
#include "vx/compiler.h"
#include "vx/source_text.h" // un solo fin de linea para todo el pipeline
#include "runtime/exception_runtime.h" // codigo de salida tras un fallo
#include "vx/vxdbg_emit.h"             // publicar el grafo del artefacto
#include "util/file_read.h"            // escribir por el camino del sistema
#include "util/file_read.h"            // escribir por el camino del sistema
#include "vxdbg/maintenance.h"         // recoger el almacen solo
#include "vxdbg/store_cli.h"           // subcomando `vm vxdbg`
#include "vx/type_checker.h"           // register_comptime_virtual_fns
#include "vx/diag/diag_format.h" // renderizado de diagnosticos (texto/JSON/SARIF)
#include "vx/lexer.h"
#include "vx/parser.h"
#include "vx/semantic_index.h"
// Forward-decl (evita incluir vx/parser.h, que arrastra cabeceras Windows que
// desbalancean el push/pop_macro(VOID) de ssa_ir.h).  @Target target-aware AOT.
namespace vx {
void set_aot_condcomp_target(const std::string &os,
                             const std::string &arch) noexcept;
}
#include "vx/comptime/comptime_vm.h" /*  MC.4 probe del ComptimeRuntime */
#include "analysis/asa/fact.h"
#include "ir/ir_optimizer.h"
#include "vx/project_cache.h"
#include "vx/source_hash.h"            /* project-level cache */
#include "vx/module/module_resolver.h" // detect_stdlib_vx_dir
#include "vx/velb_signature.h"         /*firmas digitales */
#include "util/sqlite_singleton.h"
#include "util/crono_tramo.h"
#include "util/fs_utils.h"
#include "runtime/manager_runtime.h"
#include "gc/gc_heap.h"
#include "loader/loader.h"
#include "profiler/timer.h"
#include "distrib/dist_runtime.h"
#include "distrib/dist_debug.h"
#include "distrib/node_registry.h"
#include "debug/debugger.h"
#include "debug/auth.h"

#include <filesystem>
#include <map>           // per-macro manifest map
#include <unordered_map> // layout name->offset
#include <set>           // manifest diff seen-set
#include <cctype>        // isalnum en find_macro_ranges_with_names
#include <openssl/rand.h>

#ifdef VESTA_HAS_PREPROCESSOR
#include "preprocessor/preprocessor.h"
#endif

// flag global para el modo --dist-server; SIGINT lo pone a false
static std::atomic<bool> g_server_running{true};
static void on_dist_sigint(int) {
    g_server_running.store(false);
}

/**
 * @brief Construye la NodeAuthConfig a partir de los flags de autenticacion.
 *
 * Calcula SHA-256 del token en texto plano si se proporciono --dist-token.
 * Copia las rutas TLS si se activo --dist-tls.
 *
 * @param token    Token en texto plano (puede estar vacio).
 * @param use_tls  true si se activo --dist-tls.
 * @param cert     Ruta al certificado PEM del cliente.
 * @param key      Ruta a la clave privada PEM del cliente.
 * @param ca       Ruta al CA bundle PEM para verificar pares.
 * @return NodeAuthConfig relleno.
 */
static distrib::NodeAuthConfig
build_node_auth(const std::string &token, bool use_tls, const std::string &cert,
                const std::string &key, const std::string &ca) {
    distrib::NodeAuthConfig auth{};
    if (!token.empty()) {
        auth.use_token = true;
        SHA256(reinterpret_cast<const unsigned char *>(token.c_str()),
               token.size(), auth.token_hash);
    }
    if (use_tls) {
        auth.use_tls = true;
        std::snprintf(auth.cert_path, sizeof(auth.cert_path), "%s",
                      cert.c_str());
        std::snprintf(auth.key_path, sizeof(auth.key_path), "%s", key.c_str());
        std::snprintf(auth.ca_path, sizeof(auth.ca_path), "%s", ca.c_str());
    }
    return auth;
}

/**
 * @brief Aplica la configuracion distribuida a una instancia VM.
 *
 * Reemplaza el dist_runtime minimo creado en VM::VM() por uno completamente
 * configurado segun los flags --dist-* de la linea de comandos.
 * Si --dist-port > 0 o --dist-discover esta activo, llama a start() para
 * abrir el servidor VDP y/o el hilo de descubrimiento UDP.
 * Registra cualquier nodo estatico indicado con --dist-add-node (formato
 * IP:PUERTO).
 *
 * @param vm     Instancia VM sobre la que se aplica la configuracion.
 * @param result Resultado del parseo de cxxopts con todos los flags.
 */
static void apply_dist_config(runtime::VM *vm,
                              const cxxopts::ParseResult &result) {
    const std::string token = result["dist-token"].as<std::string>();
    const bool use_tls = result.count("dist-tls") > 0;
    const std::string cert = result["dist-cert"].as<std::string>();
    const std::string key = result["dist-key"].as<std::string>();
    const std::string ca = result["dist-ca"].as<std::string>();

    // construir configuracion del DistRuntime
    distrib::DistRuntimeConfig cfg{};
    cfg.local_node_id = result["dist-node-id"].as<uint64_t>();
    cfg.vdp_listen_port = result["dist-port"].as<uint16_t>();
    cfg.discover_port = result["dist-discover-port"].as<uint16_t>();
    cfg.enable_discovery = result.count("dist-discover") > 0;

    std::string name = result["dist-name"].as<std::string>();
    if (!name.empty())
        std::snprintf(cfg.local_node_name, sizeof(cfg.local_node_name), "%s",
                      name.c_str());
    else
        std::snprintf(cfg.local_node_name, sizeof(cfg.local_node_name),
                      "vm-%llu", static_cast<unsigned long long>(vm->id));

    cfg.server_auth = build_node_auth(token, use_tls, cert, key, ca);

    // reemplazar el dist_runtime minimal por uno completamente configurado
    vm->dist_runtime = std::make_unique<distrib::DistRuntime>(*vm, cfg);

    // arrancar el servidor VDP y/o el descubrimiento si alguno esta habilitado
    if (cfg.vdp_listen_port > 0 || cfg.enable_discovery) {
        if (vm->dist_runtime->start()) {
            std::string msg = "[dist] Servidor VDP iniciado";
            if (cfg.vdp_listen_port)
                msg += " en puerto " + std::to_string(cfg.vdp_listen_port);
            if (cfg.enable_discovery)
                msg += " con descubrimiento UDP (puerto " +
                       std::to_string(cfg.discover_port) + ")";
            vesta::scout() << msg << "\n";
        } else {
            std::cerr << "[dist] Error al iniciar el servidor VDP\n";
        }
    }

    // registrar nodos estaticos proporcionados con --dist-add-node IP:PUERTO
    if (result.count("dist-add-node")) {
        distrib::NodeAuthConfig node_auth =
            build_node_auth(token, use_tls, cert, key, ca);
        for (auto &spec :
             result["dist-add-node"].as<std::vector<std::string>>()) {
            auto colon = spec.rfind(':');
            if (colon == std::string::npos) {
                std::cerr << "[dist] Formato invalido (esperado IP:PUERTO): "
                          << spec << "\n";
                continue;
            }
            std::string node_ip = spec.substr(0, colon);
            uint16_t node_port = 0;
            try {
                node_port =
                    static_cast<uint16_t>(std::stoul(spec.substr(colon + 1)));
            } catch (...) {
                std::cerr << "[dist] Puerto invalido en: " << spec << "\n";
                continue;
            }

            uint32_t idx = vm->dist_runtime->add_node(
                node_ip.c_str(), node_port, node_auth, node_ip.c_str());
            vesta::scout() << "[dist] Nodo registrado: " << node_ip << ":"
                           << node_port << " (idx=" << idx << ")\n";
        }
    }
}

/* forzar registro de virtual fns runtime (callbacks Vesta->C). */
extern "C" void runtime_ensure_vx_callback_registered(void);

// ---------------------------------------------------------------------------
//  --analyze-write: escribir las anotaciones sugeridas al fichero analizado.
//
//  Parseo textual (el IR no lleva la posicion de la declaracion): recorre el
//  fichero rastreando el nivel de llaves y el struct/class actual, y por cada
//  declaracion de funcion o metodo cuya clave este en @p anot_por_clave,
//  reemplaza las lineas de contrato que la preceden por las nuevas.  Preserva
//  @Target/@Override/comentarios ///.  Solo toca lo DEFINIDO en este fichero
//  (las funciones de imports no aparecen aqui).
//
//  Clave: funcion libre -> su nombre; metodo -> `Struct::metodo` (Struct sin
//  los type-params, para casar con la clave `plantilla::metodo` del analisis).
// ---------------------------------------------------------------------------
/**
 * @brief Vuelve a compilar con la maquina de compilacion ya cargada.
 *
 * Hay codigo que se GENERA al compilar -- una macro, un `inject(...)` que
 * devuelve el cuerpo de un bloque de asm -- y para generarlo hay que poder
 * EJECUTAR funciones del propio programa.  En la primera pasada eso todavia no
 * se puede: el bytecode que las contiene es justo lo que se esta produciendo.
 * Asi que la primera pasada deja esos sitios sin resolver, se ensambla lo que
 * hay, y con ese bytecode delante se vuelve a compilar.  La segunda es la
 * buena: sus valores son los reales, y sus `static_assert` tambien.
 *
 * Se hace aqui, en un solo sitio, porque lo necesitan TRES: la compilacion
 * normal, la nativa, y el informe.  Al informe le faltaba, y eso no era un
 * detalle: describia los bloques de asm VACIOS -- una funcion que escribe
 * sesenta y cuatro bytes por su parametro salia como si solo tocara el hueco de
 * una variable --, o sea que hablaba de un programa que no es el que se
 * compila. Y el informe es donde se mira si el compilador entendio bien.
 *
 * @param cr Resultado de la primera pasada; se SUSTITUYE por el de la segunda.
 * @param vx_path Ruta del fuente.
 * @param vx_source Su contenido (para saber si tiene imports).
 * @param copts Opciones con las que compilar la segunda pasada.
 * @param prefijo Prefijo de los ficheros temporales (sin extension).
 * @return @c true si la segunda pasada se hizo.  @c false si no hacia falta o
 *         si no se pudo ensamblar la intermedia -- ahi se conserva la primera,
 *         que es lo unico que hay.
 */
/**
 * @brief Guarda en el cache del proyecto el artefacto FINAL que se acaba de
 *        producir, con la huella de cada fuente que participo.
 *
 * Lo comparten los dos caminos que producen un artefacto -- el `.velb` de la
 * maquina virtual y el binario nativo --, porque lo que se guarda cambia pero
 * la forma de decidir si sigue valiendo es la misma: las huellas de los mismos
 * ficheros.  Tenerlo escrito dos veces era garantizar que un dia uno de los dos
 * se quedara atras.
 *
 * @param pc_path     Fichero de cache del proyecto.
 * @param opts_hash   Huella de las opciones (incluye QUE artefacto se pidio).
 * @param diag_hash   Huella de lo que decide QUE AVISOS salen, sin el
 *                    envoltorio del artefacto ni el objetivo.
 * @param donde       Objetivo en el que se compilo.  Va en cada aviso, no en la
 *                    clave: asi un solo fichero sirve a todos los objetivos y
 *                    solo se descarta lo que de verdad es de otro.
 * @param cr          Resultado del compile, por sus @c dep_paths.
 * @param con_lineas  Si la huella de cada fuente cuenta las lineas
 *                    (@c emit_debug); debe valer lo mismo al validar.
 * @param artefacto   Bytes del fichero producido.
 * @param verboso     Dejar constancia por stderr.
 */
static void
guardar_cache_de_proyecto(const std::string &pc_path, uint32_t opts_hash,
                          uint32_t diag_hash, const analysis::asa::Scope &donde,
                          const vx::CompileResult &cr, bool con_lineas,
                          const std::vector<uint8_t> &artefacto, bool verboso,
                          const std::vector<std::string> &deps_extra) {
    /* Las dependencias del compile MAS las que traiga quien llama: el fuente
     * raiz cuando no hay imports -- un fichero suelto depende de si mismo -- y
     * lo que el preprocesador haya incluido.  Se juntan aqui y no en cada sitio
     * de llamada porque la lista tiene que ser LA MISMA que se valida despues,
     * y tenerla construida en dos lados era garantizar que un dia difirieran.
     */
    std::vector<std::string> rutas = cr.dep_paths;
    for (const auto &p : deps_extra) {
        if (p.empty()) continue;
        if (std::find(rutas.begin(), rutas.end(), p) == rutas.end())
            rutas.push_back(p);
    }
    if (rutas.empty() || artefacto.empty()) return;
    std::vector<vx::ProjectCacheDep> deps;
    deps.reserve(rutas.size());
    for (const auto &p : rutas) {
        std::ifstream df(p, std::ios::binary | std::ios::ate);
        if (!df.is_open()) continue;
        const std::streamsize dsz = df.tellg();
        df.seekg(0, std::ios::beg);
        std::string texto(static_cast<size_t>(dsz < 0 ? 0 : dsz), '\0');
        if (dsz > 0) df.read(&texto[0], dsz);
        vx::ProjectCacheDep d;
        d.path = p;
        d.source_hash = vx::hash_de_tokens(texto, con_lineas);
        deps.push_back(std::move(d));
    }
    const bool guardado =
        vx::project_cache_save(pc_path, opts_hash, deps, artefacto);
    /* Y los diagnosticos con el.  Un acierto de cache sirve el artefacto sin
     * recompilar, asi que si no se guardan aqui nadie los vuelve a emitir: el
     * aviso saldria la primera vez y desapareceria despues.  Van con SU huella
     * -- la de lo que decide que avisos salen -- y no con la del artefacto, que
     * lleva formato y tipo de emision y los guardaria una vez por backend. */
    const bool diags_ok = vx::project_cache_save_diags(
        pc_path, diag_hash, cr.diagnostics.all(), donde);
    /* Y con que volver a publicar la raiz de diagnostico, por el mismo motivo
     * que los avisos: el grafo se emite durante el lowering, asi que un
     * artefacto servido desde el cache no emite ninguno y nada explicaria ese
     * binario.  Comprobado: con el cache purgado sale 1 paquete y 1 raiz; sin
     * purgar, 0 y 0.  Y recompilar no lo arregla, porque vuelve a acertar.
     *
     * No se guarda el grafo -- ya esta en su almacen y es el mismo -- sino las
     * dos huellas por las que se pregunta. */
    if (!cr.vxdbg_artifact_map.empty()) {
        vx::project_cache_save_vxdbg(pc_path, cr.vxdbg_artifact_map.to_hex(),
                                     cr.vxdbg_span_map.to_hex());
    }
    if (verboso) {
        std::cerr << "[vx-project-cache] "
                  << (guardado ? "saved" : "save_failed") << ": " << pc_path
                  << " (" << artefacto.size() << " bytes, " << deps.size()
                  << " deps, " << cr.diagnostics.all().size() << " avisos"
                  << (cr.diagnostics.all().empty() || diags_ok
                          ? ""
                          : " NO guardados")
                  << ")\n";
    }
}

/**
 * @brief Avisa si el artefacto que se va a entregar llevaria un bloque de
 *        ensamblador SIN CUERPO.
 *
 * El cuerpo de un `asm` puede generarse ejecutando codigo en compilacion.  Hoy
 * eso se escribe con el macro `inject` de `std.comptime`, que no es del
 * lenguaje: se importa como cualquier otro simbolo.  Si esa ejecucion no llega
 * a ocurrir, el bloque sale VACiO y
 * hasta ahora se compilaba igual, sin decir nada: el programa se quedaba sin la
 * copia, sin el relleno o sin lo que el bloque hiciera, y el sintoma aparecia
 * lejos del sitio -- un resultado que no cuadra, o un `hlt` a mitad de una
 * funcion de la biblioteca.  Asi se perdio una tarde persiguiendo por que el
 * mismo fuente daba un binario distinto en frio y en caliente.
 *
 * Se pregunta sobre el artefacto QUE SE ENTREGA, nunca sobre "en que pasada
 * estamos": da igual cuantas veces se compile por dentro, y el dia que se
 * compile una sola vez la comprobacion sigue valiendo sin tocarla.
 *
 * @param cr Resultado ya cerrado de la compilacion.
 * @param vx_path Fuente, para citarlo en el aviso.
 * @return @c true si habia alguno (el llamante decide si aborta).
 */
static bool warn_unresolved_inject(const vx::CompileResult &cr,
                                   const std::string &vx_path) {
    if (!cr.unresolved_inject) return false;
    vx::Diagnostic d;
    /* AVISO y no error: hoy lo dispara toda compilacion en frio que
     * importe `std.memory`, porque sus modulos se compilan ANTES de que
     * exista la maquina que genera sus cuerpos.  Convertirlo en error
     * antes de arreglar eso seria dejar el corpus sin compilar.  Cuando
     * el cuerpo este siempre disponible, esto pasa a ERROR: un bloque de
     * ensamblador sin cuerpo no es un programa valido. */
    d.level = vx::DiagLevel::WARN;
    d.code = "VXA052";
    d.args.push_back(vx_path);
    d.loc.file = vx_path;
    vx::print_diagnostic(std::cerr, d);
    return true;
}

static bool recompilar_con_maquina_de_compilacion(
    vx::CompileResult &cr, const std::string &vx_path,
    const std::string &vx_source, const vx::CompileOptions &copts,
    const std::string &prefijo) {
    if (!cr.has_lowerable_macros) return false;

    /* La intermedia se baja para la VM, SIEMPRE.  Quien la ejecuta es el
     * compilador, no el programa: con la bajada nativa hay cosas que la maquina
     * de compilacion no sabe ejecutar, y las funciones comptime con asm daban
     * cero.  Y con informacion de linea, que no lastra a nadie y hace que un
     * fallo al compilar diga fichero y linea en vez de una direccion. */
    vx::CompileOptions copts_vm = copts;
    copts_vm.native_poo = false;
    copts_vm.emit_debug = true;
    /* Y con el texto `.vel`, siempre: esta intermedia se ENSAMBLA y se ejecuta.
     * Quien la pide puede no querer artefacto para si mismo -- el informe no lo
     * quiere -- pero eso no se hereda aqui: sin `.vel` no hay nada que
     * ensamblar y no habria maquina de compilacion que ejecutar. */
    copts_vm.ir_only = false;
    /* La intermedia es la que se EJECUTA para generar el codigo, asi que se
     * compila como se compila un programa: si se le pide el trato del informe
     * -- sin inline, sin comprobaciones -- deja de parecerse al que de verdad
     * corre, y las funciones de compilacion no llegan a poder ejecutarse. */
    copts_vm.emit_ir_preopt = false;
    vx::CompileResult cr_vm =
        vx::vx_source_has_imports(vx_source)
            ? vx::compile_vx_project(vx_path, copts_vm)
            : vx::compile_vx_source(vx_source, vx_path, copts_vm);

    const std::string vel_tmp = prefijo + ".vel.tmp";
    {
        std::ofstream tmp(vel_tmp, std::ios::binary);
        if (!tmp) return false;
        if (copts_vm.emit_debug) tmp << "// @file " << vx_path << "\n";
        tmp << cr_vm.vel_text;
    }
    const int rc = asm_multi_process::run_worker(
        vel_tmp, prefijo, /*skip_preprocessor=*/true, /*keep_labels=*/false,
        /*ir_section_bytes=*/&cr_vm.ir_section_bytes, /*emit_map=*/false);
    if (rc != EXIT_SUCCESS) {
        std::remove(vel_tmp.c_str());
        return false;
    }

    const std::string velb = prefijo + ".velb";
#if defined(_WIN32)
    _putenv_s("VESTA_MC_PREBUILT", velb.c_str());
#else
    setenv("VESTA_MC_PREBUILT", velb.c_str(), 1);
#endif
    vx::CompileResult cr2 =
        vx::vx_source_has_imports(vx_source)
            ? vx::compile_vx_project(vx_path, copts)
            : vx::compile_vx_source(vx_source, vx_path, copts);
#if defined(_WIN32)
    _putenv_s("VESTA_MC_PREBUILT", "");
#else
    unsetenv("VESTA_MC_PREBUILT");
#endif
    /* La segunda manda, incluso si trae errores: puede ser un `static_assert`
     * que ha resuelto a false con el valor REAL.  Quedarse con la primera --
     * que se los salto por no poder evaluarlos -- seria dar por bueno un
     * programa con valores que no son. */
    cr = std::move(cr2);
    std::remove(vel_tmp.c_str());
    std::remove((velb + "-map").c_str());
    return true;
}

static bool annotate_write_source(
    const std::string &path, const std::vector<std::string> &orden,
    const std::map<std::string, std::string> &display,
    const std::map<std::string, std::vector<std::string>> &anot_por_clave) {
    (void)orden;
    (void)display;
    std::ifstream in(path);
    if (!in.is_open()) {
        std::cerr << "[analyze-write] no se puede abrir: " << path << "\n";
        return false;
    }
    std::vector<std::string> lin;
    {
        std::string l;
        while (std::getline(in, l)) {
            if (!l.empty() && l.back() == '\r') l.pop_back(); // CRLF
            lin.push_back(std::move(l));
        }
    }
    in.close();

    auto trim = [](const std::string &s) {
        size_t a = s.find_first_not_of(" \t");
        if (a == std::string::npos) return std::string();
        size_t b = s.find_last_not_of(" \t");
        return s.substr(a, b - a + 1);
    };
    /* Escribe una anotacion con su indentacion, repartiendola si no cabe.
     *
     * El reparto no se hace a mano: se pasa por el FORMATEADOR, que ya sabe
     * como queda un contrato largo (`R112` -- uno por linea y los valores en
     * columna).  Asi la forma se decide en un solo sitio, y anotar produce
     * directamente codigo que `vesta fmt` deja igual.
     *
     * Solo se toca la anotacion, nunca el resto del fichero: quien pidio
     * anotar no pidio reformatear su codigo. */
    auto emitir_contrato = [](std::vector<std::string> &out,
                              const std::string &ind, const std::string &a) {
        // El ancho en COLUMNAS: un tabulador de la indentacion cuenta cuatro.
        size_t ancho = a.size();
        for (const char c : ind)
            ancho += (c == '\t') ? 4 : 1;
        if (ancho <= 80) {
            out.push_back(ind + a);
            return;
        }
        const vx::fmt::FormatResult r = vx::fmt::format(a + "\n", "<contrato>");
        if (!r.ok) { // ante la duda, la linea larga antes que perderla
            out.push_back(ind + a);
            return;
        }
        /* El formateador indenta con tabuladores (`R1`), pero el fichero que
         * se anota puede estar escrito con espacios.  Pegar un tabulador
         * detras de la indentacion existente dejaria la linea a medias entre
         * los dos estilos -- y eso `R2` no lo permite --, asi que los
         * tabuladores del fragmento se traducen a lo que use el fichero. */
        const bool ind_con_tabs = ind.find('\t') != std::string::npos;
        std::istringstream ls(r.text);
        std::string linea;
        while (std::getline(ls, linea)) {
            if (!linea.empty() && linea.back() == '\r') linea.pop_back();
            if (linea.empty()) continue;
            if (!ind_con_tabs) {
                size_t t = 0;
                while (t < linea.size() && linea[t] == '\t')
                    ++t;
                if (t > 0) linea = std::string(t * 4, ' ') + linea.substr(t);
            }
            out.push_back(ind + linea);
        }
    };

    auto indent_de = [](const std::string &s) {
        size_t a = s.find_first_not_of(" \t");
        return (a == std::string::npos) ? std::string() : s.substr(0, a);
    };
    // Una linea de CONTRATO existente (a reemplazar): empieza por una de las
    // anotaciones de huella/coste, o es continuacion multilinea de una de
    // ellas (partial_/total_/when: sueltos).  @Target/@Override/// NO cuentan.
    auto es_contrato = [&](const std::string &s) {
        const std::string t = trim(s);
        static const char *pref[] = {
            "@pure",      "@nothrow",    "@nopanic",     "@alloc",
            "@stack",     "@complexity", "partial_pre:", "partial_post:",
            "total_pre:", "total_post:", "when:"};
        for (const char *p : pref)
            if (t.rfind(p, 0) == 0) return true;
        return false;
    };
    /* El `)` que cierra un contrato REPARTIDO en varias lineas (`R112`).
     *
     * Un `)` suelto no dice por si mismo de quien es, asi que se mira hacia
     * atras: si lo primero que aparece antes de el -- saltando los campos del
     * contrato -- es una linea que empieza por `@`, es su cierre.  Sin esto,
     * volver a anotar no reconocia el contrato anterior, no lo quitaba, y
     * acababa habiendo dos. */
    auto es_cierre_contrato = [&](const std::vector<std::string> &v) {
        if (v.empty() || trim(v.back()) != ")") return false;
        for (size_t k = v.size() - 1; k-- > 0;) {
            const std::string t = trim(v[k]);
            if (t.empty()) return false;
            if (t[0] == '@') return true;
            if (!es_contrato(v[k])) return false;
        }
        return false;
    };
    // Nombre de un tipo-de-retorno plausible (primer token de una decl).  No
    // hace falta ser exhaustivo: basta descartar palabras clave de sentencia.
    auto es_palabra_sentencia = [](const std::string &w) {
        static const std::set<std::string> kw = {
            "return",   "if",        "while",         "for",     "do",
            "else",     "match",     "struct",        "class",   "enum",
            "import",   "namespace", "static_assert", "asm",     "break",
            "continue", "switch",    "case",          "concept", "using",
            "typedef",  "extern",    "comptime"};
        return kw.count(w) > 0;
    };

    // Detecta si `s` declara una funcion o metodo y devuelve su nombre; "" si
    // no.  Heuristica: tiene `(`, el token justo antes del `(` es un
    // identificador, hay al menos un token de tipo antes, y NO empieza por una
    // palabra de sentencia.  El cuerpo (`{`) o el `=>` confirman la decl.
    auto nombre_decl = [&](const std::string &s) -> std::string {
        const std::string t = trim(s);
        if (t.empty() || t[0] == '/' || t[0] == '@' || t[0] == '#') return "";
        const size_t par = t.find('(');
        if (par == std::string::npos) return "";
        // El nombre es el identificador inmediatamente antes del '('.
        size_t e = par;
        while (e > 0 && (std::isspace((unsigned char)t[e - 1])))
            --e;
        size_t b = e;
        while (b > 0 &&
               (std::isalnum((unsigned char)t[b - 1]) || t[b - 1] == '_'))
            --b;
        if (b == e) return "";
        const std::string nombre = t.substr(b, e - b);
        if (nombre.empty() ||
            (!std::isalpha((unsigned char)nombre[0]) && nombre[0] != '_'))
            return "";
        // Debe haber algo ANTES del nombre (el tipo de retorno / modificadores)
        // -> descarta llamadas `foo(...)`.  Y el primer token no puede ser una
        // palabra de sentencia (`return foo(...)`, `if (...)`).
        const std::string antes = trim(t.substr(0, b));
        if (antes.empty()) return "";
        std::string primero = antes;
        size_t sp = primero.find_first_of(" \t");
        if (sp != std::string::npos) primero = primero.substr(0, sp);
        if (es_palabra_sentencia(primero)) return "";
        // Confirma que parece una definicion: la linea acaba en `{`, `=>`, `;`
        // (decl sin cuerpo) o el `(` abre parametros de una decl (heuristica:
        // hay un `)` con `{`/`=>` cerca -- aceptamos si acaba en `{` o `=>` o
        // contiene `) {` / `) =>`).
        if (t.find("{") != std::string::npos ||
            t.find("=>") != std::string::npos)
            return nombre;
        return ""; // p.ej. una llamada multilinea; conservador
    };

    // Una pasada del reescritor: recorre `src` rastreando llaves + la pila de
    // struct/class, y sustituye los contratos que preceden a cada decl casada.
    // Devuelve las lineas resultantes y cuantas decl se anotaron.
    struct Ctx {
        std::string nombre;
        int nivel;
    };
    auto apply_once = [&](const std::vector<std::string> &src)
        -> std::pair<std::vector<std::string>, size_t> {
        std::vector<Ctx> pila;
        int nivel = 0;
        std::string struct_pendiente; // visto `struct X` esperando su `{`
        std::vector<std::string> out;
        size_t reemplazos = 0;

        for (const auto &l : src) {
            const std::string t = trim(l);

            // Apertura de struct/class: recordar el nombre hasta ver su `{`.
            {
                std::string kw;
                if (t.rfind("struct ", 0) == 0)
                    kw = t.substr(7);
                else if (t.rfind("class ", 0) == 0)
                    kw = t.substr(6);
                else if (t.rfind("public struct ", 0) == 0)
                    kw = t.substr(14);
                else if (t.rfind("public class ", 0) == 0)
                    kw = t.substr(13);
                if (!kw.empty()) {
                    size_t e = 0;
                    while (e < kw.size() &&
                           (std::isalnum((unsigned char)kw[e]) || kw[e] == '_'))
                        ++e;
                    struct_pendiente = kw.substr(0, e);
                }
            }

            // Declaracion de funcion/metodo?
            const std::string nom = nombre_decl(l);
            if (!nom.empty()) {
                // Clave: metodo generico -> `Plantilla::metodo`; no generico ->
                // mangled `Struct__metodo`.  Se prueban ambas formas.
                auto it = anot_por_clave.end();
                if (!pila.empty()) {
                    const std::string &st = pila.back().nombre;
                    it = anot_por_clave.find(st + "::" + nom);
                    if (it == anot_por_clave.end())
                        it = anot_por_clave.find(st + "__" + nom);
                } else {
                    it = anot_por_clave.find(nom);
                }
                // Fallback funcion libre: sufijo (namespace -> `ns__nom`).
                if (it == anot_por_clave.end() && pila.empty()) {
                    for (auto k = anot_por_clave.begin();
                         k != anot_por_clave.end(); ++k) {
                        const std::string &c = k->first;
                        if (c.size() > nom.size() + 2 &&
                            c.compare(c.size() - nom.size() - 2, nom.size() + 2,
                                      "__" + nom) == 0) {
                            it = k;
                            break;
                        }
                    }
                }
                if (it != anot_por_clave.end()) {
                    // Quitar los contratos ya emitidos (contiguos arriba),
                    // repartidos en varias lineas incluidos.
                    while (!out.empty() &&
                           (es_contrato(out.back()) || es_cierre_contrato(out)))
                        out.pop_back();
                    const std::string ind = indent_de(l);
                    for (const auto &a : it->second)
                        emitir_contrato(out, ind, a);
                    ++reemplazos;
                }
            }

            out.push_back(l);

            for (char c : l) {
                if (c == '{') {
                    if (!struct_pendiente.empty()) {
                        pila.push_back({struct_pendiente, nivel});
                        struct_pendiente.clear();
                    }
                    ++nivel;
                } else if (c == '}') {
                    --nivel;
                    if (!pila.empty() && pila.back().nivel == nivel)
                        pila.pop_back();
                }
            }
        }
        return {std::move(out), reemplazos};
    };

    auto pr = apply_once(lin);
    const std::vector<std::string> &out = pr.first;
    const size_t reemplazos = pr.second;

    if (reemplazos == 0) {
        std::cout << "[analyze-write] " << path
                  << ": ninguna funcion/metodo de este fichero tenia contrato "
                     "que actualizar (las de imports se anotan analizando su "
                     "propio fichero).\n";
        return true;
    }

    // Salvaguarda: aplicar el reescritor sobre su propia salida.  Si una 2a
    // pasada la cambiaria, el mapeo texto->decl no es estable -> NO tocar el
    // fichero (mejor abortar que corromperlo).
    auto pr2 = apply_once(out);
    if (pr2.first != out) {
        std::cerr << "[analyze-write] " << path
                  << ": el reescritor no es estable sobre su salida (posible "
                     "decl ambigua); no se toca el fichero.\n";
        return false;
    }

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) {
        std::cerr << "[analyze-write] no se puede escribir: " << path << "\n";
        return false;
    }
    for (const auto &l : out)
        ofs << l << "\n";
    ofs.close();
    std::cout << "[analyze-write] " << path << ": " << reemplazos
              << " funcion(es)/metodo(s) anotados.  Re-ejecuta --analyze para "
                 "verificar (0 discrepancias).\n";
    return true;
}

int main(int argc, char *argv[]) {
#if defined(_WIN32) && !defined(__CYGWIN__)
    /* Consola en UTF-8, para que la salida con acentos o simbolos no salga
     * rota en la consola de Windows.
     *
     * Esto es exactamente lo que hace `chcp 65001`, que es como se hacia:
     * lanzando el comando.  Pero lanzarlo significa crear un `cmd.exe` entero
     * con sus tuberias, y eso cuesta unos 10-20 ms EN CADA invocacion del
     * binario -- se pagaba al compilar, al ejecutar y al pedir la version, y
     * era la mayor parte del arranque de un programa corto.  La API hace lo
     * mismo en microsegundos.
     *
     * Sin consola (salida redirigida a un fichero o a una tuberia) las dos
     * llamadas fallan y no pasa nada: no hay pagina de codigos que ajustar. */
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    runtime_ensure_vx_callback_registered();
    // i18n: seleccionar el idioma de los diagnosticos desde el entorno
    // (VESTA_LANG > LC_ALL > LANG; fallback al primer idioma del catalogo).
    vx::diag::set_language(vx::diag::language_from_env());
    //  AS inc.4b: registrar el backend de ensamblado Keystone para que el
    // frontend Vesta valide la sintaxis del inline asm en compile-time.
    jit::register_keystone_asm_backend();
    //  AS inc.6: registrar el helper nativo vrt:inline_asm_exec que el
    // interprete (modo -m vm, sin JIT) invoca por cada bloque inline-asm.
    jit::register_inline_asm_runner();
    // Bug/feature 198: registrar el dispatcher vrt:naked_dispatch que
    // compila+invoca funciones @Naked (asm con simbolos propios) al vuelo
    // desde interp/JIT, + vrt:naked_fnaddr (direccion nativa de una funcion
    // para punteros a funcion que fluyen a codigo nativo).
    jit::register_naked_dispatch_runner();
    jit::register_naked_fnaddr_runner();

    // Las funciones virtuales del compilador (`vesta_comptime`) tambien tienen
    // que estar registradas al EJECUTAR: un `.velb` puede llevar un cuerpo
    // comptime como codigo muerto -- el de un constructor comptime, por
    // ejemplo -- cuyo import se resuelve al cargar, antes de saber que nadie
    // lo va a llamar.  Sin esto el FFI buscaba una DLL que no existe y el
    // programa moria al arrancar.
    vx::register_comptime_virtual_fns();
    // FN.3: registrar vrt:jit_active (modo interp vs JIT) y vrt:getproc
    // (ProcessVM* actual), que `fiber_init` usa para elegir el modelo de
    // fibra en JIT (pila/ctx host + trampolin + proc).
    jit::register_fiber_runtime_runner();

    // ------------------------------------------------------------------
    // Subcomando especial: @c vm pkg <subcmd> ...
    // Despachamos ANTES del parser cxxopts porque el package manager
    // tiene su propio sistema de flags y subcomandos.
    // ------------------------------------------------------------------
    if (argc >= 2 && std::string(argv[1]) == "pkg") {
        // Pasamos argv shifted: argv[0]="vm", argv[1]="pkg",
        // queremos que pkg::cli reciba argv[1]=primer subcomando.
        // Construimos un argc/argv nuevo skipeando el "pkg" literal.
        std::vector<char *> sub;
        sub.push_back(argv[0]);
        for (int i = 2; i < argc; ++i)
            sub.push_back(argv[i]);
        return pkg::cli::run(static_cast<int>(sub.size()), sub.data());
    }

    /* ------------------------------------------------------------------
     * Subcomando: @c vesta fmt [check|print] <ficheros...>
     *
     * Va con `pkg` y `vxdbg` y no con las opciones porque dar formato no
     * modifica una compilacion: es una herramienta aparte, con sus ordenes.
     * Y va ANTES del parser de opciones para que sus argumentos sean suyos.
     * ------------------------------------------------------------------ */
    if (argc >= 2 && std::string(argv[1]) == "fmt") {
        std::vector<char *> sub;
        sub.push_back(argv[0]);
        for (int i = 2; i < argc; ++i)
            sub.push_back(argv[i]);
        return vx::fmt::cli::run(static_cast<int>(sub.size()), sub.data());
    }

    /* ------------------------------------------------------------------
     * Subcomando: @c vesta lint <fichero.vx>
     *
     * Va con `fmt`, `pkg` y `vxdbg` y no con las opciones porque pasar el
     * linter NO modifica una compilacion: es una herramienta aparte, con sus
     * argumentos.  Mezclarla con las opciones del compilador dejaria que
     * conviviera con `-o`, `--format` o `--emit`, que aqui no significan nada.
     * ------------------------------------------------------------------ */
    if (argc >= 2 && std::string(argv[1]) == "lint") {
        std::vector<char *> sub;
        sub.push_back(argv[0]);
        for (int i = 2; i < argc; ++i)
            sub.push_back(argv[i]);
        return analyze::lint_cli::run(static_cast<int>(sub.size()), sub.data());
    }

    // ------------------------------------------------------------------
    // Subcomando especial: @c vm vxdbg <orden> ...
    // Igual que `pkg`: no modifica una compilacion, opera sobre el almacen
    // de diagnostico y tiene sus propias ordenes.
    // ------------------------------------------------------------------
    if (argc >= 2 && std::string(argv[1]) == "vxdbg") {
        std::vector<char *> sub;
        sub.push_back(argv[0]);
        for (int i = 2; i < argc; ++i)
            sub.push_back(argv[i]);
        return vxdbg::cli::run(static_cast<int>(sub.size()), sub.data());
    }

    /* registrar el hook auto-JIT en el runtime.
     * El runtime (vesta_rt) tiene un function pointer nulo por defecto;
     * el main aqui lo apunta al JIT trigger.  Si el env var
     * VESTA_JIT_THRESHOLD esta presente, el trigger compila funciones
     * hot a codigo nativo.  Sin env var, el
     * threshold queda en UINT32_MAX y el hook es no-op aunque se llame. */
    runtime::g_callvirt_post_hook = &jit::maybe_compile_method;

    cxxopts::Options options("VMProject", "Virtual Machine Example");

    options.add_options()("h,help", "Mostrar ayuda")(
        "o,output", "Archivo de salida (sin extensión o completo)",
        cxxopts::value<std::string>())(
        "driver", "Compilar un directorio completo en paralelo",
        cxxopts::value<std::string>())(
        "worker", "Compilar un único archivo (modo interno)",
        cxxopts::value<std::string>())(
        "j,threads", "Número de hilos para el driver",
        cxxopts::value<int>()->default_value("0"))("v,version",
                                                   "Mostrar versión")(
        "m,mode",
        "Modo de ejecucion/compilacion: vm (interprete) | jit (JIT en "
        "caliente) | aot (compilacion nativa standalone, requiere --vx)",
        cxxopts::value<std::string>()->default_value("vm"))(
        "diag-format",
        "Formato de los diagnosticos: text (legible, default) | json | sarif "
        "(SARIF 2.1.0 para IDEs/CI). El idioma del texto se elige con "
        "VESTA_LANG.",
        cxxopts::value<std::string>()->default_value("text"))(
        "list-arch", "Imprimir arquitecturas soportadas")(
        "asm-file", "Archivo ASM a ensamblar", cxxopts::value<std::string>())(
        "disasm-file", "Archivo binario a desensamblar",
        cxxopts::value<std::string>())(
        "arch", "Arquitectura para ensamblar/desensamblar",
        cxxopts::value<std::string>())(
        "save-output", "Guardar código ensamblado/desensamblado en archivo")(
        "output-prefix", "Prefijo/nombre base para archivos de salida",
        cxxopts::value<std::string>()->default_value("out"))(
        "run", "Ejecutar un archivo .velb en la VM",
        cxxopts::value<std::string>())("build",
                                       "Compilar un archivo .vel a .velb",
                                       cxxopts::value<std::string>())(
        "schedulers", "Número de schedulers para el comando run",
        cxxopts::value<size_t>()->default_value("1"))(
        "stats",
        "Mostrar estadísticas de ejecución al finalizar (tiempo, MIPS)")
        // ---- opciones de JIT ----
        ("jit-threshold",
         "Umbral de invocaciones de un metodo para disparar JIT (default: "
         "UINT32_MAX = JIT off; sugerido para test: 1)",
         cxxopts::value<uint32_t>())(
            "jit-warn", "Imprimir warnings cada vez que el Selector encuentra "
                        "una IR op no soportada (dedup por op+linea)")(
            "jit-stats", "Imprimir snapshot final de counters del JIT: "
                         "compiled/unsupported/no_ir + threshold")(
            "jit-disasm", "Volcar hex bytes + disasm (Capstone) de cada "
                          "funcion JIT-compilada a stderr")(
            "cpu",
            "Microarquitectura objetivo para el scheduler (p.ej. "
            "intel-skylake, "
            "amd-zen3, intel-icelake).  Usa los datos EXACTOS de "
            "latencia/puertos "
            "de la DB.  Sin --cpu: JIT auto-detecta el host; AOT usa el "
            "generico.",
            cxxopts::value<std::string>())
        // ---- opciones de profiling (D.6 PGO) ----
        ("profile",
         "PGO.  Al EJECUTAR (--run): genera '<path>.vprof' (branch/type/alloc "
         "counters) y '<path>.lines' (perfil de branches por linea fuente, "
         "requiere compilar con --vex-debug).  Al COMPILAR (--vx): carga "
         "'<path>.lines' para las decisiones de if-conversion (PGO).",
         cxxopts::value<std::string>()->implicit_value("program.vprof"))
        // ---- opciones de runtime distribuido ----
        ("dist-port",
         "Puerto VDP del servidor distribuido (0 = sin servidor TCP)",
         cxxopts::value<uint16_t>()->default_value("0"))(
            "dist-discover", "Activar descubrimiento UDP de nodos en la LAN")(
            "dist-discover-port", "Puerto UDP para descubrimiento de nodos",
            cxxopts::value<uint16_t>()->default_value("7790"))(
            "dist-name", "Nombre del nodo local (cadena identificativa)",
            cxxopts::value<std::string>()->default_value(""))(
            "dist-node-id",
            "ID de 64 bits del nodo (0 = generar automaticamente)",
            cxxopts::value<uint64_t>()->default_value("0"))(
            "dist-add-node",
            "Nodo estatico a registrar y conectar (formato IP:PUERTO, "
            "repetible)",
            cxxopts::value<std::vector<std::string>>())(
            "dist-token",
            "Token de autenticacion en texto plano (se almacena como SHA-256)",
            cxxopts::value<std::string>()->default_value(""))(
            "dist-tls", "Usar TLS en las conexiones VDP salientes y entrantes")(
            "dist-cert", "Ruta al certificado TLS del nodo local (PEM)",
            cxxopts::value<std::string>()->default_value(""))(
            "dist-key", "Ruta a la clave privada TLS del nodo local (PEM)",
            cxxopts::value<std::string>()->default_value(""))(
            "dist-ca", "Ruta al CA bundle TLS para verificar pares (PEM)",
            cxxopts::value<std::string>()->default_value(""))(
            "dist-server", "Modo servidor distribuido puro: espera conexiones "
                           "VDP sin ejecutar bytecode")(
            "dist-debug", "Activar trazas de depuracion del subsistema "
                          "distribuido (RSPAWN, HALT, FUTURE_FULFILL)")(
            "script", "Ejecutar un fichero VestaShell (.vsh) y salir",
            cxxopts::value<std::string>())(
            "interprete",
            "Abrir el interprete interactivo VestaShell (REPL .vsh)")(
            "ir-file",
            "Compilar archivo .ir (SSA IR) a .vel y opcionalmente a .velb",
            cxxopts::value<std::string>())(
            "ir-opt",
            "Nivel de optimizacion IR: 0=O0, 1=O1, 2=O2, 3=O3 (defecto: 1)",
            cxxopts::value<int>()->default_value("1"))(
            "ir-emit-only", "Solo emitir el texto .vel; no compilar a .velb")(
            "vesta", "Compilar archivo .vx (lenguaje Vesta) a .velb",
            cxxopts::value<std::string>())(
            "vx", "Alias de --vesta (compilar archivo .vx a .velb)",
            cxxopts::value<std::string>())(
            "vx-emit-only",
            "Escribir ademas el .vel intermedio del .vx (por defecto se queda "
            "en memoria); el .velb se genera igual")(
            "vx-emit-ir",
            "Emitir el SSA IR del .vx (pre y post optimizacion) en "
            "<output>.ir; util para debug del frontend")(
            "dump-semantic-index",
            "Volcar el indice semantico por-declaracion (hash de contenido + "
            "grafo de deps) de un .vx como JSON; sustrato de la compilacion "
            "incremental granular",
            cxxopts::value<std::string>())(
            "analyze",
            "Subsistema de coste: analiza la complejidad algoritmica (Big-O) "
            "estatica de cada funcion de un .vx y la imprime; valida el "
            "contrato @complexity si esta presente. Cero impacto en codegen.",
            cxxopts::value<std::string>())(
            "analyze-json",
            "Con --analyze: emite el coste por funcion como JSON (para "
            "consumir desde un renderer de diagramas) en vez de texto "
            "legible.")(
            "asa",
            "Vuelca TODO lo que el compilador sabe de un .vx: cada afirmacion "
            "con su dominio, su certeza, de donde sale y de que otros hechos "
            "se "
            "sigue; y tambien lo que se miro SIN sacar nada, con el motivo.  "
            "Sin "
            "variantes: lo vuelca entero y se redirige a un fichero.",
            cxxopts::value<std::string>())(
            "analyze-write",
            "Con --analyze: ESCRIBE las anotaciones sugeridas al fichero "
            "analizado (reemplaza las de contrato existentes de cada funcion/"
            "metodo definido ahi).  Re-verifica antes de guardar; si algo no "
            "cuadra, no toca el fichero.  Las funciones de imports no se tocan "
            "(analiza ese fichero por separado).")
        //  AOT: con -m aot, target de compilacion nativa.
        ("target",
         "Tier de compilacion nativa AOT (-m aot): bare|embed|full (default "
         "bare).",
         cxxopts::value<std::string>()->default_value("bare"))(
            "freestanding",
            "AOT bare sin libc (kernels/bootloaders): RAW_ALLOC/FREE/PANIC "
            "requieren hooks @AllocatorOverride/@PanicHandler.")(
            "no-exceptions",
            "AOT (-m aot): DESACTIVA el mecanismo de excepciones nativo "
            "(setjmp/longjmp).  Un try/catch/throw da error.  Para "
            "kernels/freestanding sin runtime de excepciones.")(
            "no-io",
            "AOT (-m aot): NO auto-incluye el runtime de I/O "
            "(stdlib/vx/vx_io.vx).  El usuario aporta __vx_write y los "
            "__vx_print_* (p.ej. enlazar vesta_io_bare.o, o freestanding).")(
            "no-mem",
            "AOT (-m aot): NO auto-incluye el slab allocator "
            "(stdlib/vx/vx_mem.vx).  El allocator usa libc malloc/free (o el "
            "@AllocatorOverride del usuario).")(
            "format",
            "Formato del ejecutable AOT (-m aot): pe|elf (default: PE en "
            "Windows, ELF en el resto).",
            cxxopts::value<std::string>())(
            "no-pie", "AOT: refs a datos absolutas (mov reg,imm64; requiere "
                      "base de imagen fija) en vez de RIP-relativas (default, "
                      "position-independent), analogo a gcc/clang -no-pie.")(
            "emit",
            "AOT: tipo de artefacto: exe (ejecutable standalone, default) | "
            "obj (objeto relocatable linkable: ELF .o o COFF .obj segun "
            "--format) | shared (libreria compartida ELF .so que exporta sus "
            "funciones; dlopen/dlsym) | bin (binario plano sin cabecera: "
            "bootloader/ROM/firmware, entry en offset 0).",
            cxxopts::value<std::string>())(
            "bin-base",
            "AOT --emit bin: base de carga del binario plano (hex, e.g. "
            "0x7C00); afecta solo a refs absolutas (--no-pie). Default 0.",
            cxxopts::value<std::string>())(
            "aot-arch",
            "AOT: arquitectura objetivo: x86-64 (default) | x86-32 (modo "
            "protegido, kernels: 8 GP eax-edi, regparm(3), subset entero de "
            "32-bit).",
            cxxopts::value<std::string>()->default_value("x86-64"))(
            "debug-info",
            "Nivel de info de depuracion (flag UNIVERSAL, todos los targets).  "
            "Un eje por MECANISMO, separados por punto: <dwarf>[.<lenguaje>].  "
            "Son cosas distintas y se piden por separado -- el primero lo "
            "consumen depuradores y desensambladores AJENOS (gdb, WinDbg, "
            "lldb, valgrind), el segundo es el nuestro.  "
            "DWARF: 0=ninguna (default, cero coste) | 1=simbolos de funcion "
            "(.symtab/COFF en ELF/PE/.o/.so/.dll) | 2=+lineas (futuro) | "
            "3=+variables (futuro).  "
            "LENGUAJE: 0=ninguna (default) | 1=fichero acompanante .vxdbg con "
            "funcion, linea, columna y tramo (NO toca el binario: el codigo "
            "emitido es el mismo byte a byte).  "
            "Ejemplos: 1 (=1.0, solo DWARF, como siempre) | 0.1 (solo el "
            "nuestro) | 1.1 (los dos).",
            cxxopts::value<std::string>()->default_value("0"))(
            "float-isa",
            "AOT: backend de punto flotante / ancho SIMD del vectorizador: "
            "sse2 (default, 128b, corre en CUALQUIER x86-64) | x87 (legacy) | "
            "avx (AVX2 256b, requiere AVX2 en la CPU) | avx512f (512b, "
            "requiere "
            "AVX-512) | auto (multiversion: emite las 3 variantes y elige la "
            "optima en runtime por CPUID; lo mejor para distribuir un solo "
            "binario). Nota: un binario avx/avx512f FIJO da SIGILL en una CPU "
            "sin ese soporte; usa auto para portabilidad.",
            cxxopts::value<std::string>()->default_value("sse2"))(
            "ffp-contract",
            "Politica de contraccion de coma flotante: fast (default -- "
            "contrae "
            "a*b+c en FMA, 1 redondeo, como gcc/clang) | off (IEEE estricto, 2 "
            "redondeos, sin FMA).  Global; @fp(strict|fast) lo override por "
            "funcion.",
            cxxopts::value<std::string>()->default_value("fast"))(
            "vx-base",
            "VA base address para el modulo (hex, e.g. 0x10000000). Usado para "
            "plugins cargados via loadmodule, evita solapamiento con el caller "
            "(default 0x0).",
            cxxopts::value<std::string>()->default_value("0x0"))
        //  M.sandbox: restringe las capabilities del modulo
        // principal al subset listado.  Default vacio = ALL granted
        // (zero overhead, backward compat).  Sintaxis: 'fs:read,net,
        // ffi:call=kernel32.dll;user32.dll' etc.  Ver include/loader/
        // sandbox.h para tabla completa de caps + sintaxis.
        ("vx-caps",
         " M.sandbox: restringe caps del modulo principal. Sintaxis: "
         "'fs:read,net,ffi:call=kernel32.dll;user32.dll'. Vacio = ALL granted "
         "(default). 'none' = sandbox total.",
         cxxopts::value<std::string>()->default_value(""))
        // Diagramas para debug y traceo del pipeline Vesta.  Tres formatos
        // seleccionables via --diagram-format:
        //   mermaid (default): escribe .mmd con bloque ```mermaid```;
        //                      listo para VS Code / GitHub / mermaid.live.
        //   graphviz:          escribe .dot con `digraph G { ... }`;
        //                      listo para `dot -Tsvg foo.dot -o foo.svg`.
        //   html:              escribe .html interactivo AUTOCONTENIDO
        //                      (CSS+JS embebidos, sin CDN): pan/zoom, panel
        //                      de detalle por nodo, busqueda, filtros de
        //                      aristas.  Se abre directo en el navegador.
        //   both:              mermaid + graphviz.   all: los tres.
        // El contenido es paralelo entre formatos: misma topologia, misma
        // info por nodo (Graphviz/HTML llevan extra via tooltips/detalle).
        // --diagram-all genera las 4 vistas (AST, IR pre, IR post, VEL)
        // en el formato escogido.
        ("diagram-vx",
         "Generar diagrama del AST Vesta post type-check (.ast.<ext>)")(
            "diagram-ir",
            "Generar diagrama del SSA IR pre-optimizacion (.ir.pre.<ext>)")(
            "diagram-ir-opt",
            "Generar diagrama del SSA IR post-optimizacion (.ir.post.<ext>)")(
            "diagram-vel",
            "Generar diagrama del bytecode .vel final (.vel.<ext>)")(
            "diagram-all", "Generar las 4 vistas (vx, ir pre, ir post, vel) "
                           "con sufijos correspondientes")(
            "diagram-format",
            "Formato: mermaid | graphviz | html | both | all (default: "
            "mermaid). html produce paginas interactivas autocontenidas "
            "(.html); both=mermaid+graphviz; all=los tres.",
            cxxopts::value<std::string>()->default_value("mermaid"))(
            "gc-debug",
            "Activar trazas de debug del Garbage Collector a stderr (minor_gc, "
            "major_gc, sweep, release_handle, evacuate). Util para "
            "diagnosticar use-after-free o objetos colectados prematuramente. "
            "Alt: env VESTA_GC_DEBUG=1.")(
            "gc-debug-buffered",
            "Activar modo BUFFERED del GC debug: ~100x mas rapido (buffer "
            "thread-local de 64KB) pero pierde las ultimas trazas en crash. "
            "Implica --gc-debug. Alt: env VESTA_GC_DEBUG_BUFFERED=1.")(
            "debug-port",
            "Activar el servidor de depuracion TCP en el puerto N (default "
            "9229 si N=0). Soporta multiples clientes simultaneos y JSON via "
            "length-prefix framing. El servidor permanece disponible mientras "
            "la VM ejecuta; los clientes (e.g. tools/dbg_client.vsh) se "
            "conectan via tcp_connect, envian comandos JSON y reciben eventos "
            "asincronos (break/exit/exception/spawned). Sin este flag, el "
            "debugger NO se instancia y el coste runtime es exactamente cero. "
            "Cuando esta presente, el proceso main arranca PAUSADO en su "
            "primera instruccion para dar tiempo al cliente a conectarse y "
            "poner breakpoints; el cliente debe enviar 'continue 0' para "
            "arrancar la ejecucion.",
            cxxopts::value<uint16_t>()->default_value("0"))(
            "server-mode",
            "Iniciar la VM como un servidor persistente de depuracion. Implica "
            "--debug-port (default 9229). No requiere --run: la VM se queda "
            "viva esperando comandos del debugger para cargar/ejecutar/matar "
            "procesos remotamente. Compatible con --schedulers, --dist-port, "
            "etc. Termina con SIGINT (Ctrl+C) o con el comando "
            "'server_shutdown' del cliente. Comandos disponibles: load_velb, "
            "load_velb_bytes, kill_proc, server_info, server_shutdown, "
            "auth_login/logout/whoami, "
            "auth_create_user/delete_user/list_users/change_pass, "
            "fs_read/write/list/stat/delete/mkdir/rename.")(
            "server-port",
            "Puerto del servidor persistente (sinonimo de --debug-port en modo "
            "--server-mode). Default 9229.",
            cxxopts::value<uint16_t>()->default_value("0"))(
            "server-root",
            "Directorio raiz del sandbox de filesystem en modo --server-mode. "
            "Todas las rutas usadas por fs_* y load_velb se resuelven contra "
            "este directorio; cualquier intento de salir (con '..' o rutas "
            "absolutas) se rechaza. Sin este flag NO hay sandbox (modo "
            "back-compat: cualquier ruta absoluta del servidor es accesible). "
            "Recomendado en despliegues compartidos.",
            cxxopts::value<std::string>()->default_value(""))(
            "auth-db",
            "Ruta al fichero SQLite con la tabla vm_users (usuarios, hashes "
            "PBKDF2 y roles) en modo --server-mode. Sin este flag la "
            "autenticacion esta desactivada y cualquier cliente puede invocar "
            "cualquier comando (modo desarrollo).",
            cxxopts::value<std::string>()->default_value(""))(
            "admin-user",
            "Nombre del usuario admin a crear automaticamente cuando la base "
            "de datos --auth-db esta vacia. Default 'admin'.",
            cxxopts::value<std::string>()->default_value("admin"))(
            "admin-password",
            "Contrasenya del usuario admin a crear automaticamente. Si se "
            "omite y --auth-db apunta a una BD vacia, se genera una "
            "contrasenya aleatoria de 24 caracteres y se imprime en stdout UNA "
            "UNICA VEZ.",
            cxxopts::value<std::string>()->default_value(""))(
            "no-repl",
            "Desactivar el REPL interactivo local en modo --server-mode (modo "
            "headless). Sin este flag, el operador local mantiene un prompt "
            "vesta> que comparte el mismo runtime con los clientes remotos; "
            "con el, el proceso solo escucha el socket TCP.")(
            "vx-debug",
            "Emitir comentarios `// @line N` en el .vel intermedio del "
            "compilador Vesta y, cuando se integre la pipeline completa de "
            "debug "
            "section ( 2), embeber la tabla bytecode_offset -> (file, "
            "line) en el .velb final.  Sin este flag, el .vel/.velb no "
            "contienen info de debug -> el ejecutable es mas pequeno y el "
            "frontend NO genera datos extra.  Con el flag, el cliente del "
            "debugger puede setear breakpoints por linea Vesta (`b "
            "file.vx:42`) "
            "en lugar de solo por addr.")(
            "vxdbg-dir",
            "Carpeta donde volcar la base de conocimiento de depuracion: los "
            "tipos del programa, sus miembros y como se relacionan, cada uno "
            "identificado por su contenido.  Es informacion APARTE del "
            "ejecutable -- no cambia ni un byte de lo que se genera -- y sirve "
            "para explicar un fallo en terminos del fuente en lugar de "
            "direcciones.  Sin este flag no se emite nada.",
            cxxopts::value<std::string>()->default_value(""))(
            "no-debug-info",
            "Desactivar la emision del mapa PC -> linea (seccion DVBG) en el "
            ".velb.  Por defecto el mapa SE EMITE (barato en tamano, no cambia "
            "el codigo) para habilitar el auto-PGO del JIT (mapear los "
            "contadores de branches medidos a su linea fuente) y mejores stack "
            "traces.  Usa este flag para .velb minimos sin info de debug.")(
            "port",
            "Transpilar el IR a codigo fuente del lenguaje destino y escribir "
            "a <output>.<ext> (e.g. .c).  Valores actuales: 'c'.  Futuro: "
            "'java', 'js', 'rust'.  Con --port=c se genera codigo C99 portable "
            "listo para compilar con gcc/clang -O3 -std=c11 SIN dependencias "
            "de VestaVM (a menos que --port-gc=vesta).  Implica --vx (se "
            "aplica al pipeline Vesta post-optimizacion).",
            cxxopts::value<std::string>())(
            "emit-header",
            "Generar el header C publico del modulo (<output>.h): typedefs de "
            "los structs C-compatibles + prototipos de las funciones con firma "
            "C-representable + punteros a funcion cfn.  Pensado junto a --port "
            "c: el .c lleva las definiciones y el .h las declaraciones, listo "
            "para que un programa C incluya el .h y enlace el .c.")(
            "port-gc",
            "Modelo de memoria del codigo portado: none|vesta|boehm.  none "
            "(default): malloc/free + sin GC.  Las IR ops de objetos GC "
            "(NEWOBJ/strings) emiten stub.  vesta: enlazar contra "
            "vesta_rt.lib.  boehm: enlazar contra libgc (placeholder).",
            cxxopts::value<std::string>()->default_value("none"))(
            "port-exc",
            "Manejo de excepciones del codigo portado: none|setjmp|returncode. "
            " none: throw -> abort.  setjmp (default): longjmp portable.  "
            "returncode: codigo de retorno + propagacion explicita (no impl "
            "v1).",
            cxxopts::value<std::string>()->default_value("setjmp"))(
            "port-types",
            "Estilo de tipos del codigo portado: stdint (default) usa "
            "int8_t/uint64_t/etc de stdint.h.  builtin usa char/int/long del C "
            "clasico (menos portable).",
            cxxopts::value<std::string>()->default_value("stdint"))(
            "port-strings",
            "Modelo de strings: raw (const char* solo literales) | managed "
            "(default: VxString con tracking per-thread).",
            cxxopts::value<std::string>()->default_value("managed"))(
            "port-freestanding",
            "Generar C freestanding (sin includes automaticos de "
            "stdio/stdlib/math).  El usuario debe proveer vx_throw + "
            "vx_panic_with_str.  Para bootloaders, kernels, firmware.")(
            "port-stdlib-dir",
            "Path al directorio stdlib/port/c con los snippets .v.c "
            "(autodetect si vacio).",
            cxxopts::value<std::string>()->default_value(""))(
            "port-arch",
            "Target CPU: '' (portable, default) | native | x86-64-v2 | "
            "x86-64-v3 | x86-64-v4.  Emite #pragma GCC target con flags "
            "agresivas (AVX2/FMA/BMI2 segun nivel).",
            cxxopts::value<std::string>()->default_value(""))(
            "port-no-aggressive",
            "Desactivar atributos agresivos (const/cold/restrict/always_inline "
            "+ __builtin_expect/unreachable).  Default: activado.")(
            "instrument",
            "Instrumentacion en el IR Vesta (heredada por bytecode VM, JIT, "
            "port "
            "C, port futuros): none (default) | trace (calls a "
            "vx_trace:enter/exit por funcion) | profile (timing per-funcion).",
            cxxopts::value<std::string>()->default_value("none"))
#ifdef VESTA_HAS_PREPROCESSOR
            ("preprocess-only",
             "Solo preprocesar un .vel y mostrar/guardar el resultado (debug)",
             cxxopts::value<std::string>())
#endif
                ("keep-labels",
                 "Mantener los nombres de label en el .velb (por defecto se "
                 "eliminan: el loader no los usa y reducen ~9% el tamano)")(
                    "emit-map", "Generar archivo .velb-map con info de "
                                "simbolos y secciones (debug). Off por "
                                "defecto: cuesta ~60% del tiempo del linker")
        //  M.L28: firmas digitales del .velb.
        ("sign-velb",
         "Firmar un .velb con clave privada PEM. Uso: --sign-velb input.velb "
         "--sign-key priv.pem -o output.signed.velb",
         cxxopts::value<std::string>())(
            "sign-key", "Path al PEM con la clave privada para --sign-velb",
            cxxopts::value<std::string>())(
            "verify-velb",
            "Verificar la firma digital de un .velb. Uso: --verify-velb "
            "file.velb --verify-key pub.pem",
            cxxopts::value<std::string>())(
            "verify-key", "Path al PEM con la clave publica para --verify-velb",
            cxxopts::value<std::string>())
        //  AOT.5: linker propio (enlaza .o sin ld/gcc).
        ("link",
         " AOT.5: enlaza objetos relocatables (ELF64 o COFF AMD64, "
         "auto-detectados; los de --emit obj o de gcc/MSVC) en un ejecutable "
         "nativo SIN ld/gcc. Uso: vm --link a.o b.o [lib.a] [lib.dll] -o prog "
         "[--format elf|pe] [--entry sym] [--link-base 0xADDR]. Con --entry "
         "usa "
         "ese simbolo como entrada SIN stub (kernel/bootloader); sin el, "
         "sintetiza _start->main (ejecutable hosted).")
        //  AOT.5: archivador propio (crea .a sin el ar del sistema).
        ("ar",
         " AOT.5: crea una libreria estatica .a (formato ar GNU, con "
         "indice de simbolos) a partir de objetos, SIN el ar del sistema. Uso: "
         "vm --ar libfoo.a a.o b.o ...  El .a lo consume nuestro linker "
         "(--link) "
         "y tambien ar/ld/gcc.")(
            "entry",
            "Con --link: simbolo de entrada del ejecutable (e.g. _kstart). "
            "Vacio => _start sintetico que llama a main.",
            cxxopts::value<std::string>()->default_value(""))(
            "link-base",
            "Con --link: base de carga del ejecutable (hex, e.g. 0x100000 para "
            "un kernel). Default segun el formato.",
            cxxopts::value<std::string>()->default_value(""))(
            "link-script",
            "Con --link: script de enlace ESCRITO EN VESTA (un .vx con 'fn "
            "link()' que llama a builtins base/entry/stack/section/"
            "section_size/align_up/debug_build). El linker lo compila y "
            "ejecuta "
            "para leer la configuracion. Los CLI --link-base/--entry tienen "
            "prioridad sobre el script.",
            cxxopts::value<std::string>()->default_value(""))(
            "link-debug",
            "Con --link --link-script: hace que el builtin debug_build() del "
            "script devuelva true.",
            cxxopts::value<bool>()->default_value("false"))(
            "sysroot",
            "Con --link / --emit exe (ELF): raiz donde buscar las librerias "
            "del "
            "sistema (libc.so.6) al cross-compilar ELF desde otro SO. En Linux "
            "nativo no hace falta.",
            cxxopts::value<std::string>()->default_value(""));

    // BUG FIX: Args posicionales y allow_unrecognised DEBEN configurarse
    // ANTES de @c options.parse(...).  El bug anterior registraba el
    // option `positional` y @c parse_positional DESPUES del parse, asi
    // que cualquier `vm --script foo.vsh arg1 arg2` perdia arg1/arg2 y
    // ARGV del script quedaba con solo el path del script.  Se mueve
    // toda la configuracion arriba; esto es prerequisito de @c parse.
    options.add_options()("positional", "Argumentos posicionales",
                          cxxopts::value<std::vector<std::string>>());
    options.parse_positional({"positional"});
    options.positional_help("[args...]");
    options
        .allow_unrecognised_options(); // para flags sin que aun hay que parsear

    auto result = options.parse(argc, argv);

    // activar trazas de depuracion del subsistema distribuido si se paso
    // --dist-debug
    if (result.count("dist-debug")) distrib::set_dist_debug(true);

    // activar trazas del GC si se paso --gc-debug.  Tambien respeta env
    // VESTA_GC_DEBUG=1 (la inicializacion estatica corre antes de main,
    // no se pierde si el flag CLI esta o no).
    if (result.count("gc-debug")) gc::set_gc_debug(true);
    // --gc-debug-buffered implica --gc-debug ademas de buffered mode.
    if (result.count("gc-debug-buffered")) {
        gc::set_gc_debug(true);
        gc::set_gc_debug_buffered(true);
    }

    // ---- Configuracion del JIT ----
    //
    // Orden de prioridad (mayor primero):
    //   1. --jit-threshold N   (CLI explicito)
    //   2. -m jit              (preset = threshold 1, util para tests)
    //   3. VESTA_JIT_THRESHOLD env var (default ya lazy-leida en auto_jit)
    //
    // --jit-warn activa el output detallado de IR ops no soportadas.
    // --jit-stats imprime el snapshot final al RET de main (independiente).
    /* Prioridad: --jit-threshold > -m jit/-m interp explicito > env var
     * VESTA_JIT_THRESHOLD > default (UINT32_MAX = JIT off).
     *
     * cxxopts retorna count("mode") == 0 cuando no se paso `-m` aunque
     * la opcion tenga default_value("vm").  Usamos eso para distinguir
     * "el usuario eligio -m algo" vs "default; mirar env var".
     *
     * Importante: leer el env var ANTES del Loader para que la
     * eager-compile pass se dispare con el threshold correcto.  Sin esto
     * el threshold se inicializa lazy en el primer maybe_compile_*, ya
     * tarde para eager compile. */
    //  AOT: modo de compilacion nativa standalone (-m aot).  Se resuelve
    // aqui (junto al resto de modos) y se consume en el bloque --vx mas abajo.
    bool aot_mode = false;
    aot::Tier aot_tier = aot::Tier::BARE;
    bool aot_freestanding = result.count("freestanding") > 0;
    bool aot_no_exceptions = result.count("no-exceptions") > 0;
    bool aot_no_io = result.count("no-io") > 0;
    bool aot_no_mem = result.count("no-mem") > 0;
    {
        const std::string &tname = result["target"].as<std::string>();
        if (tname == "bare")
            aot_tier = aot::Tier::BARE;
        else if (tname == "embed")
            aot_tier = aot::Tier::EMBED;
        else if (tname == "full")
            aot_tier = aot::Tier::FULL;
        else {
            std::cerr << "[aot] --target invalido: '" << tname
                      << "' (usa bare|embed|full)\n";
            return EXIT_FAILURE;
        }
    }

    // --cpu: microarquitectura objetivo del scheduler (datos exactos de la DB).
    if (result.count("cpu"))
        jit::sched::set_sched_cpu(result["cpu"].as<std::string>());

    // -ffp-contract=off: IEEE estricto (sin contraccion FMA).  Global; el AOT y
    // @fp(strict) lo pueden refinar despues.
    if (result.count("ffp-contract") &&
        result["ffp-contract"].as<std::string>() == "off")
        ir::ir_set_fma_contract_allowed(false);

    if (result.count("jit-threshold")) {
        jit::set_jit_threshold(result["jit-threshold"].as<uint32_t>());
    } else if (result.count("mode")) {
        const std::string m = result["mode"].as<std::string>();
        if (m == "jit") {
            jit::set_jit_threshold(1);
        } else if (m == "vm" || m == "interp") {
            jit::set_jit_threshold(UINT32_MAX);
        } else if (m == "aot") {
            // Modo AOT: no se ejecuta nada en la VM; el JIT runtime queda off.
            aot_mode = true;
            jit::set_jit_threshold(UINT32_MAX);
            // FMA en AOT: la contraccion escalar es ORTOGONAL a --float-isa
            // (que controla el ancho SIMD).  Default = ON (la mayoria de CPUs
            // tienen FMA3; VFMADD231SD no depende del ancho vectorial).  Solo
            // se desactiva con -ffp-contract=off, o si --cpu apunta a una
            // microarq SIN FMA (la DB lo sabe -> evita SIGILL en ese target
            // concreto).
            {
                const bool ffp_off =
                    result.count("ffp-contract") &&
                    result["ffp-contract"].as<std::string>() == "off";
                bool fma_ok = !ffp_off;
                if (result.count("cpu")) {
                    const std::string cpu_s = result["cpu"].as<std::string>();
                    if (!cpu_s.empty() && cpu_s != "generic")
                        fma_ok =
                            fma_ok && jit::backend_caps_from_cpu(cpu_s).fma;
                }
                ir::ir_set_fma_contract_allowed(fma_ok);
                jit::set_vreg_fma(fma_ok);
            }
            // @Target target-aware: los atomos os:/arch: de @Target se evaluan
            // contra el TARGET del binario AOT (cross-compile), no el host de
            // build, para que las variantes por plataforma del runtime/usuario
            // se seleccionen segun --format / --aot-arch.
            std::string fmt_s;
            if (result.count("format"))
                fmt_s = result["format"].as<std::string>();
            else
#if defined(_WIN32)
                fmt_s = "pe";
#else
                fmt_s = "elf";
#endif
            const std::string arch_s =
                result.count("aot-arch") ? result["aot-arch"].as<std::string>()
                                         : std::string("x86-64");
            // La arquitectura del objetivo la traduce el registro que la
            // define; decidirla aqui con un booleano dejaba a aarch64
            // evaluando los `@Target` como x86-64.
            vx::set_aot_condcomp_target(fmt_s == "pe" ? "windows" : "linux",
                                        vx::cwhen::normalize_arch(arch_s));
            // Camino de compilacion: lo que hace utilizable
            // @Target("mode:aot") frente a @Target("mode:bytecode").
            vx::set_aot_condcomp_mode("aot");
            // Y cuanto runtime hay debajo, que es lo que contesta a
            // `@Target("tier:bare")` / `embed` / `full` -- los mismos nombres
            // que toma `--target` --, mas `tier:sin_libc` para
            // `--freestanding`.
            vx::set_aot_condcomp_tier(aot_tier == aot::Tier::FULL    ? "full"
                                      : aot_tier == aot::Tier::EMBED ? "embed"
                                                                     : "bare",
                                      aot_freestanding);
        }
    } else {
        /* Sin flags CLI explicitos -> consultar env var ahora.  Lo
         * hacemos via la API publica que delega en el mismo
         * std::call_once que el path lazy interno, asi futuras
         * inicializaciones lazy son no-op (idempotente). */
        jit::init_threshold_from_env_now();
    }
    if (result.count("jit-warn")) {
        jit::g_jit_warn_unsupported = true;
    }
    if (result.count("jit-disasm")) {
        jit::g_jit_disasm = true;
    }
    /* Sprint D.6 (2026-06-03): activar profile counters runtime.  El
     * --profile [path] inicializa el collector y registra el atexit
     * handler para dump automatico al finalizar el proceso.  Tambien
     * se respeta la env var VESTA_PROFILE_DUMP cuando el flag no esta. */
    {
        std::string profile_path;
        if (result.count("profile")) {
            profile_path = result["profile"].as<std::string>();
        } else {
            profile_path = util::flag_text(util::FlagId::ProfileDump);
        }
        if (!profile_path.empty()) {
            runtime::profile::profile_init(profile_path);
        }
    }
    /* Auto-PGO del JIT (default-ON): si el JIT esta habilitado (threshold !=
     * MAX), activar el profiler LIGERO (lock-free, tabla fija) desde el
     * arranque para que tier-0 recolecte branches y el JIT re-decida la
     * if-conversion con el perfil medido -- sin que el usuario pida nada.
     * Escape VESTA_NO_JIT_PGO =1.  El profiler ligero tiene coste ~1 ciclo por
     * branch, apto para always-on.  El pesado D.6 (--profile) es aparte. */
    {
        const bool jit_on = (jit::g_jit_threshold != UINT32_MAX);
        if (jit_on && !util::flag_on(util::FlagId::NoJitPgo)) {
            runtime::profile::lite_profile_set_active(true);
            jit::g_jit_tier2_on = true; // guard barato del tier-2 en CALLVIRT
        }
    }
    const bool jit_stats_requested = result.count("jit-stats") > 0;
    /* Sprint string-perf-6: --stats o --jit-stats activan el counter MIPS
     * per-block en JIT.  Sin estos flags el JIT corre sin overhead de
     * instrumentacion (35-50% mas rapido en hot loops con muchos bloques). */
    if (result.count("stats") || jit_stats_requested) {
        jit::g_jit_emit_instr_counter = true;
    }

    if (result.count("help")) {
        vesta::scout() << options.help() << std::endl;
        vesta::scout() <<
            R"(Variables de entorno:

  CTPE (precomputo del programa completo en tiempo de compilacion):
    Ejecuta el main puro (sin I/O, FFI ni memoria cross-proceso) durante la
    compilacion e inyecta su resultado como constante.  Activo por defecto.
    VESTA_NO_CTPE            Desactiva CTPE.
    VESTA_CTPE_MS=N          Presupuesto del watchdog en ms (default 3000); si
                             el main tarda mas, se aborta y corre en runtime.
    VESTA_CTPE_DEBUG=1       Traza el analisis (funciones evaluables + candidato).

  JIT:
    VESTA_JIT_THRESHOLD=N    Invocaciones para disparar auto-JIT en runtime
                             (UINT32_MAX = desactivado; equivale a -m vm).
    VESTA_JIT_WARN_UNSUPPORTED=1  Avisa de ops IR que el selector no compila.
    VESTA_JIT_DISASM=1       Vuelca el codigo nativo JIT-eado (hex + disasm).

  Optimizacion:
    VESTA_NO_ESCAPE_SCALAR=1 Desactiva el scalar-replacement de objetos GC.
    VESTA_ESCAPE_DEBUG=1     Traza los veredictos del escape analysis.

  Compilacion modular / cache:
    VX_PARALLEL_COMPILE=N    Threads de compilacion (0 = auto, 1 = secuencial).
    VX_NO_CACHE              Ignora el cache incremental de modulos.
    VX_CACHE_DIR=ruta        Directorio del cache (default .cache/vex).
    VX_CACHE_FINGERPRINT=x   Fija la huella del compilador que entra en la
                             clave del cache.  Por defecto se toma del propio
                             ejecutable, de modo que recompilarlo invalida los
                             artefactos.  Fijarla permite instrumentar el
                             compilador sin perder el cache que reproduce un
                             fallo que se esta investigando.
    VX_TREE_SHAKE=1          Elimina simbolos no usados entre modulos.
    VX_VERBOSE_COMPILE=1     Muestra el progreso de compilacion por modulo.
    VESTA_LINKER_PROFILE=1   Perfila las fases del linker.

  Perfilado (PGO):
    VESTA_PROFILE_DUMP=ruta  Ruta del .vprof (o usa --profile).
)" << std::endl;
        return 0;
    }

    std::string out_prefix;
    if (result.count("output")) {
        out_prefix = result["output"].as<std::string>();
    } else {
        out_prefix = result["output-prefix"].as<std::string>();
    }

    if (result.count("version")) {
        cli::print_version_banner(std::cout);
        return 0;
    }

    if (result.count("list-arch")) {
        const ArchSupport &archs = get_available_architectures();
        vesta::scout() << "Capstone supported architectures:\n";
        for (auto &a : archs.capstone)
            vesta::scout() << "  " << a << "\n";
        vesta::scout() << "Keystone supported architectures:\n";
        for (auto &a : archs.keystone)
            vesta::scout() << "  " << a << "\n";
        return 0;
    }

    // === Validacion temprana de combinaciones de flags ===
    // Sin esto, flags incompatibles o mal escritas se ignoraban en silencio
    // por el orden de dispatch.  Ejemplos reales detectados:
    //   - `--run x.velb -m aot --emit exe --format exe`: el dispatch de --run
    //     ganaba y ejecutaba el .velb, ignorando -m aot/--emit/--format.
    //   - `--vx x.vx --emit exe` (sin -m aot): --emit se ignoraba en silencio.
    // Falla cerrado con mensaje claro en vez de hacer algo distinto a lo
    // pedido.
    {
        // (1) Acciones primarias mutuamente excluyentes: solo una a la vez.
        static const char *const kPrimaryActions[] = {
            "run", "worker",   "driver",      "build", "vesta",
            "vx",  "asm-file", "disasm-file", "script"};
        std::vector<std::string> present;
        for (const char *a : kPrimaryActions)
            if (result.count(a)) present.emplace_back(std::string("--") + a);
        if (present.size() > 1) {
            std::cerr << "[cli] acciones incompatibles: ";
            for (size_t i = 0; i < present.size(); ++i)
                std::cerr << (i ? ", " : "") << present[i];
            std::cerr << " -- elige solo una.\n";
            return EXIT_FAILURE;
        }

        // (2) -m aot solo tiene sentido compilando un .vx a binario nativo.
        if (aot_mode && !result.count("vesta") && !result.count("vx")) {
            std::cerr << "[cli] -m aot requiere --vesta <archivo.vx> "
                         "(compilacion nativa desde fuente Vesta).\n";
            if (result.count("run"))
                std::cerr << "[cli]   nota: --run ejecuta un .velb en la VM; "
                             "es incompatible con -m aot.\n";
            return EXIT_FAILURE;
        }

        // (3) --emit / --format solo aplican a la compilacion AOT (-m aot) o,
        //     en el caso de --format, al linker propio (--link).  Fuera de esos
        //     contextos se ignoraban sin avisar.
        const bool link_mode = result.count("link") > 0;
        /* El ANALISIS tambien elige objetivo.  Este compilador cruza -- genera
         * un ELF de Linux desde Windows --, asi que analizar solo para el
         * anfitrion dejaba fuera justo el codigo que mas se quiere revisar: el
         * de la otra plataforma.  Con `--format elf` se pedia y se rechazaba,
         * y sin el, un `@Target("... && !os:windows")` se excluye y el fichero
         * ni siquiera compila para analizarlo. */
        const bool analyze_mode = result.count("analyze") > 0;
        if (result.count("emit") && !aot_mode) {
            std::cerr << "[cli] --emit solo aplica con -m aot "
                         "(compilacion nativa standalone).\n";
            return EXIT_FAILURE;
        }
        if (result.count("format") && !aot_mode && !link_mode &&
            !analyze_mode) {
            std::cerr << "[cli] --format solo aplica con -m aot, --link o "
                         "--analyze.\n";
            return EXIT_FAILURE;
        }
    }

    //  M.L28: firmas digitales del .velb (independientes del flujo
    // de compile / run / etc.).  Ambos comandos retornan al usuario al
    // terminar; no continuan al resto del flow.
    if (result.count("sign-velb")) {
        const std::string in_path = result["sign-velb"].as<std::string>();
        if (!result.count("sign-key")) {
            std::cerr << "error: --sign-velb requiere --sign-key <priv.pem>\n";
            return EXIT_FAILURE;
        }
        const std::string key_path = result["sign-key"].as<std::string>();
        const std::string out_path = result.count("output")
                                         ? result["output"].as<std::string>()
                                         : (in_path + ".signed");
        std::ifstream f(in_path, std::ios::binary | std::ios::ate);
        if (!f) {
            std::cerr << "error: no se puede abrir " << in_path << "\n";
            return EXIT_FAILURE;
        }
        const std::streamsize sz = f.tellg();
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> bytes(static_cast<size_t>(sz < 0 ? 0 : sz));
        if (sz > 0) f.read(reinterpret_cast<char *>(bytes.data()), sz);
        f.close();
        std::vector<uint8_t> signed_bytes;
        std::string err;
        if (!vx::velb_sign(bytes, key_path, vx::VsigAlgo::RSA_SHA256,
                           signed_bytes, err)) {
            std::cerr << "error: " << err << "\n";
            return EXIT_FAILURE;
        }
        std::ofstream of(out_path, std::ios::binary);
        if (!of) {
            std::cerr << "error: no se puede escribir " << out_path << "\n";
            return EXIT_FAILURE;
        }
        of.write(reinterpret_cast<const char *>(signed_bytes.data()),
                 static_cast<std::streamsize>(signed_bytes.size()));
        std::cerr << "[sign] " << in_path << " (" << bytes.size() << " B) -> "
                  << out_path << " (" << signed_bytes.size() << " B, +"
                  << (signed_bytes.size() - bytes.size())
                  << " B footer VSIG)\n";
        return EXIT_SUCCESS;
    }

    if (result.count("verify-velb")) {
        const std::string in_path = result["verify-velb"].as<std::string>();
        if (!result.count("verify-key")) {
            std::cerr
                << "error: --verify-velb requiere --verify-key <pub.pem>\n";
            return EXIT_FAILURE;
        }
        const std::string key_path = result["verify-key"].as<std::string>();
        std::ifstream f(in_path, std::ios::binary | std::ios::ate);
        if (!f) {
            std::cerr << "error: no se puede abrir " << in_path << "\n";
            return EXIT_FAILURE;
        }
        const std::streamsize sz = f.tellg();
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> bytes(static_cast<size_t>(sz < 0 ? 0 : sz));
        if (sz > 0) f.read(reinterpret_cast<char *>(bytes.data()), sz);
        f.close();
        auto vr = vx::velb_verify_signature(bytes, key_path);
        if (vr.ok) {
            std::cerr << "[verify] " << in_path << ": firma VALIDA\n";
            return EXIT_SUCCESS;
        }
        std::cerr << "[verify] " << in_path << ": " << vr.error << "\n";
        return EXIT_FAILURE;
    }

    //  AOT.5: linker propio -- enlaza objetos .o en un ejecutable nativo
    // sin depender de ld/gcc.  Uso: vm --link a.o b.o -o prog [--format elf]
    // [--entry sym] [--link-base 0xADDR].
    if (result.count("ar")) {
        // Archivador propio: vm --ar libfoo.a a.o b.o ...  (primer posicional =
        // .a de salida; resto = objetos), o -o libfoo.a + posicionales objetos.
        std::vector<std::string> pos;
        if (result.count("positional"))
            pos = result["positional"].as<std::vector<std::string>>();
        std::string ar_out =
            result.count("output") ? result["output"].as<std::string>() : "";
        std::vector<std::string> ar_objs;
        if (!ar_out.empty()) {
            ar_objs = pos; // -o fijo la salida; los posicionales son objetos
        } else if (!pos.empty()) {
            ar_out = pos.front(); // primer posicional = salida
            ar_objs.assign(pos.begin() + 1, pos.end());
        }
        if (ar_out.empty() || ar_objs.empty()) {
            std::cerr
                << "error: --ar requiere la libreria de salida y al menos "
                   "un objeto (vm --ar libfoo.a a.o [b.o ...])\n";
            return EXIT_FAILURE;
        }
        std::string aerr;
        if (!aot::aot_ar_create(ar_out, ar_objs, aerr)) {
            std::cerr << "[ar] error: " << aerr << "\n";
            return EXIT_FAILURE;
        }
        std::cerr << "[ar] '" << ar_out << "' creado (" << ar_objs.size()
                  << " objeto(s)).\n";
        return EXIT_SUCCESS;
    }

    if (result.count("link")) {
        std::vector<std::string> inputs;
        if (result.count("positional"))
            inputs = result["positional"].as<std::vector<std::string>>();
        if (inputs.empty()) {
            std::cerr << "error: --link requiere al menos un objeto .o "
                         "(vm --link a.o [b.o ...] -o salida)\n";
            return EXIT_FAILURE;
        }
        aot::LinkOptions lopts;
        // Formato: --format pe|elf (default ELF; slice 1 = ELF).
        if (result.count("format")) {
            const std::string fmt = result["format"].as<std::string>();
            if (fmt == "pe")
                lopts.fmt = aot::ObjFormat::PE;
            else if (fmt == "elf")
                lopts.fmt = aot::ObjFormat::ELF;
            else {
                std::cerr << "error: --format invalido para --link: " << fmt
                          << " (pe|elf)\n";
                return EXIT_FAILURE;
            }
        } else {
            lopts.fmt = aot::ObjFormat::ELF;
        }
        lopts.entry = result["entry"].as<std::string>();
        const std::string lbase = result["link-base"].as<std::string>();
        if (!lbase.empty())
            lopts.image_base =
                std::strtoull(lbase.c_str(), nullptr, 0); // 0x.. o decimal
        lopts.link_script = result["link-script"].as<std::string>();
        lopts.debug = result.count("link-debug") > 0;
        lopts.sysroot = result["sysroot"].as<std::string>();
        std::string out_path = result["output"].as<std::string>();
        std::string lerr;
        if (!aot::aot_link(inputs, out_path, lopts, lerr)) {
            std::cerr << "[link] error: " << lerr << "\n";
            return EXIT_FAILURE;
        }
        /* Y se marca ejecutable.  Enlazar produce algo que se EJECUTA, pero el
         * emisor abre el fichero con `fopen(path,"wb")`, que en POSIX lo crea
         * sin ese bit: salia un ELF valido que daba `Permission denied` al
         * lanzarlo, sin que nada hubiera fallado.  El compilador nativo ya lo
         * hacia; este camino no, y en Windows no se ve porque ahi ese bit no
         * existe -- por eso aguanto tanto sin que nadie lo notara. */
        if (!fs::mark_executable(out_path))
            std::cerr << "[link] aviso: no se pudo marcar '" << out_path
                      << "' como ejecutable.\n";
        std::string entry_note =
            !lopts.entry.empty()
                ? (", entry=" + lopts.entry)
                : (lopts.link_script.empty() ? std::string(", _start->main")
                                             : std::string(", entry via "
                                                           "link-script"));
        std::cerr << "[link] ejecutable '" << out_path << "' escrito ("
                  << inputs.size() << " objeto(s)" << entry_note << ").\n";
        return EXIT_SUCCESS;
    }

#ifdef VESTA_HAS_PREPROCESSOR
    // Solo preprocesar: expandir macros y directivas sin ensamblar
    // vm.exe --preprocess-only src/main.vel [-o salida.vel]
    if (result.count("preprocess-only")) {
        const std::string &src_path =
            result["preprocess-only"].as<std::string>();

        // leer el archivo fuente
        std::ifstream ifs(src_path, std::ios::binary);
        if (!ifs) {
            std::cerr << "error: no se puede abrir: " << src_path << "\n";
            return EXIT_FAILURE;
        }
        std::string source((std::istreambuf_iterator<char>(ifs)),
                           std::istreambuf_iterator<char>());

        // configurar el preprocesador igual que run_worker
        vpp::Preprocessor pp;
        std::string source_dir =
            std::filesystem::path(src_path).parent_path().string();
        if (source_dir.empty()) source_dir = ".";
        pp.options().include_paths.push_back(source_dir);
        std::string exe_dir = std::filesystem::path(fs::get_executable_path())
                                  .parent_path()
                                  .string();
        pp.options().import_paths.push_back(exe_dir +
                                            "/preprocessor/include_lib");
        pp.options().import_paths.push_back(exe_dir + "/include_lib");
        {
            std::string _plib =
                std::filesystem::path(exe_dir).parent_path().string();
            if (!_plib.empty()) {
                pp.options().import_paths.push_back(_plib + "/include_lib");
                pp.options().import_paths.push_back(
                    _plib + "/preprocessor/include_lib");
            }
        }
        pp.options().import_paths.push_back(source_dir);
#ifdef _WIN32
        pp.options().predefines.push_back("__VPP_WINDOWS__");
#elif defined(__linux__)
        pp.options().predefines.push_back("__VPP_LINUX__");
#elif defined(__APPLE__)
        pp.options().predefines.push_back("__VPP_MACOS__");
#endif
#if defined(__x86_64__) || defined(_M_X64)
        pp.options().predefines.push_back("__VPP_X86_64__");
#elif defined(__i386__) || defined(_M_IX86)
        pp.options().predefines.push_back("__VPP_X86_32__");
#elif defined(__aarch64__) || defined(_M_ARM64)
        pp.options().predefines.push_back("__VPP_AARCH64__");
#endif

        std::string processed = pp.process(source, src_path);

        // imprimir todos los diagnosticos
        for (const auto &d : pp.diagnostics().diagnostics()) {
            std::cerr << d.loc.file() << ":" << d.loc.line << ":" << d.loc.col
                      << ": "
                      << (d.level >= vpp::DiagLevel::ERR ? "error: "
                                                         : "warning: ")
                      << d.message << "\n";
        }
        if (pp.diagnostics().has_errors()) return EXIT_FAILURE;

        // escribir a archivo si se especifico -o, si no a stdout
        if (!out_prefix.empty() && out_prefix != "out") {
            // determinar nombre del archivo de salida
            std::string out_file = out_prefix;
            if (out_file.find('.') == std::string::npos) out_file += ".vel";
            std::ofstream ofs(out_file);
            if (!ofs) {
                std::cerr << "error: no se puede escribir: " << out_file
                          << "\n";
                return EXIT_FAILURE;
            }
            ofs << processed;
            vesta::scout() << "[preprocess-only] -> " << out_file << "\n";
        } else {
            // sin -o: imprimir a stdout para inspeccion rapida
            std::cout << processed;
        }
        return EXIT_SUCCESS;
    }
#endif

    // -----------------------------------------------------------------------
    // Modo servidor distribuido puro (sin ejecutar bytecode)
    // vm.exe --dist-server --dist-port 7789 [--dist-discover] [--dist-name
    // nodo1]
    //        [--dist-add-node 192.168.1.100:7789] [--dist-token secreto]
    //        [--dist-tls --dist-cert cert.pem --dist-key key.pem --dist-ca
    //        ca.pem]
    // -----------------------------------------------------------------------
    if (result.count("dist-server")) {
        try {
            runtime::ManageVM dist_mgr(nullptr, 0);
            runtime::VM *vm = dist_mgr.loader.create_vm_instance(1);
            if (!vm) {
                std::cerr << "[dist-server] Error: no se pudo crear la "
                             "instancia VM\n";
                return EXIT_FAILURE;
            }

            apply_dist_config(vm, result);

            // activar modo persistente para que el scheduler no termine al no
            // haber procesos; los procesos remotos llegan via rspawn despues
            // del arranque
            vm->vm_persistent = true;
            vm->start();

            vesta::scout() << "[dist-server] Nodo distribuido activo. "
                              "Pulse Ctrl+C para detener.\n";

            // esperar hasta Ctrl+C
            std::signal(SIGINT, on_dist_sigint);
            while (g_server_running.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(100));

            vm->dist_runtime->stop();
            vm->stop();
            vesta::scout() << "[dist-server] Nodo detenido.\n";
        } catch (const std::exception &e) {
            std::cerr << "[dist-server] Error: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // Modo servidor persistente de depuracion (sin ejecutar un .velb inicial).
    //
    // vm.exe --server-mode [--server-port N | --debug-port N] [--schedulers M]
    //        [--dist-port ...] [--vx-debug]
    //
    // La VM se queda viva indefinidamente atendiendo comandos del debugger
    // (load_velb, kill_proc, server_info, server_shutdown, etc.).  Los
    // clientes (tools/dbg_client.vsh o el IDE Electron) pueden conectarse,
    // cargar .velb desde el filesystem de la VM, lanzarlos como procesos y
    // gestionarlos via los comandos normales del protocolo de depuracion.
    //
    // Termina con SIGINT (Ctrl+C) o con el comando server_shutdown del cliente.
    // -----------------------------------------------------------------------
    if (result.count("server-mode")) {
        try {
            size_t num_schedulers = result["schedulers"].as<size_t>();
            runtime::ManageVM mgr(nullptr, 0);
            runtime::VM *vm = mgr.loader.create_vm_instance(num_schedulers);
            if (!vm) {
                std::cerr << "[server-mode] Error: no se pudo crear la "
                             "instancia VM\n";
                return EXIT_FAILURE;
            }

            // Aplicar configuracion distribuida si el usuario paso flags
            // --dist-*
            bool has_dist = result.count("dist-port") > 0 ||
                            result.count("dist-discover") > 0 ||
                            result.count("dist-add-node") > 0 ||
                            result.count("dist-tls") > 0 ||
                            result.count("dist-name") > 0 ||
                            result.count("dist-token") > 0 ||
                            result.count("dist-node-id") > 0;
            if (has_dist) apply_dist_config(vm, result);

            // Resolver puerto: --server-port > --debug-port > default 9229
            uint16_t srv_port = 0;
            if (result.count("server-port"))
                srv_port = result["server-port"].as<uint16_t>();
            if (srv_port == 0 && result.count("debug-port"))
                srv_port = result["debug-port"].as<uint16_t>();
            if (srv_port == 0) srv_port = debug::DBG_DEFAULT_PORT;

            // Configuracion del sandbox de filesystem.
            std::string srv_root = result["server-root"].as<std::string>();
            if (!srv_root.empty()) {
                std::error_code rec;
                std::filesystem::create_directories(srv_root, rec);
            }

            // Configuracion del AuthManager.
            std::string auth_db = result["auth-db"].as<std::string>();
            bool auth_enabled = !auth_db.empty();
            if (auth_enabled) {
                if (!debug::AuthManager::instance().init(auth_db)) {
                    std::cerr
                        << "[server-mode] Error: "
                        << debug::AuthManager::instance().last_init_error()
                        << "\n";
                    std::cerr << "[server-mode] Sugerencia: usa una ruta "
                                 "absoluta a un directorio escribible, "
                                 "p.ej. --auth-db \"C:\\Users\\TuUsuario\\"
                                 "VestaVM\\users.db\".\n";
                    return EXIT_FAILURE;
                }
                // Bootstrap del admin si la BD esta vacia.
                if (!debug::AuthManager::instance().has_any_user()) {
                    std::string admin_user =
                        result["admin-user"].as<std::string>();
                    std::string admin_pass =
                        result["admin-password"].as<std::string>();
                    if (admin_pass.empty()) {
                        // Generar contrasenya aleatoria de 24 chars base64.
                        uint8_t raw[18];
                        if (RAND_bytes(raw, sizeof(raw)) != 1) {
                            std::cerr
                                << "[server-mode] Error: RAND_bytes "
                                   "fallo al generar la contrasenya admin\n";
                            return EXIT_FAILURE;
                        }
                        static const char *alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ"
                                                      "abcdefghijkmnpqrstuvwxyz"
                                                      "23456789";
                        admin_pass.reserve(24);
                        for (size_t i = 0; i < 24; ++i)
                            admin_pass.push_back(alphabet[raw[i % 18] % 62]);
                    }
                    std::string e;
                    if (!debug::AuthManager::instance().create_user(
                            admin_user, admin_pass, debug::Role::ADMIN, &e)) {
                        std::cerr << "[server-mode] Error: no se pudo crear "
                                     "el admin: "
                                  << e << "\n";
                        return EXIT_FAILURE;
                    }
                    vesta::scout() << "[server-mode] Usuario admin creado: '"
                                   << admin_user << "'\n";
                    vesta::scout()
                        << "[server-mode] Contrasenya admin (SOLO se "
                           "muestra una vez): "
                        << admin_pass << "\n";
                }
            }

            // Arrancar el servidor de depuracion ANTES de iniciar la VM.
            auto dbg = std::make_unique<debug::Debugger>(*vm);
            dbg->set_server_root(srv_root);
            dbg->set_auth_required(auth_enabled);
            if (!dbg->start(srv_port)) {
                std::cerr << "[server-mode] Error: no se pudo iniciar el "
                             "servidor de depuracion en puerto "
                          << srv_port << "\n";
                return EXIT_FAILURE;
            }
            vm->debugger = dbg.get();
            // NO activamos `sched->has_hooks=true` aqui: el debugger lo
            // hara automaticamente via @c refresh_scheduler_hooks cuando
            // el primer breakpoint / step / watch llegue.  Si no hay
            // depuracion activa, los schedulers se quedan en el fast
            // path threaded computed-goto y el coste runtime es 0%.

            // Modo persistente: el scheduler espera nuevos procesos en
            // lugar de terminar al quedarse sin trabajo.  Cuando un cliente
            // hace load_velb, el proceso resultante entra en READY y el
            // scheduler lo recoge sin necesidad de reiniciar nada.
            vm->vm_persistent = true;
            vm->start();

            vesta::scout() << "[server-mode] VM persistente activa.\n";
            vesta::scout() << "[server-mode] Debugger TCP escuchando en "
                              "puerto "
                           << srv_port << ".\n";
            vesta::scout() << "[server-mode] Schedulers: " << num_schedulers
                           << ".\n";
            if (!srv_root.empty()) {
                vesta::scout()
                    << "[server-mode] Sandbox de filesystem: " << srv_root
                    << "\n";
            } else {
                vesta::scout() << "[server-mode] Sin sandbox de filesystem "
                                  "(use --server-root para restringir).\n";
            }
            if (auth_enabled) {
                vesta::scout() << "[server-mode] Auth: ACTIVO (BD: " << auth_db
                               << ").  Los clientes deben "
                                  "invocar auth_login.\n";
            } else {
                vesta::scout() << "[server-mode] Auth: DESACTIVADO (modo "
                                  "desarrollo; use --auth-db <ruta> para "
                                  "exigir login).\n";
            }
            // Conectar el flag global con el debugger para que el comando
            // server_shutdown remoto lo pueda mover.
            std::signal(SIGINT, on_dist_sigint);
            debug::set_server_shutdown_flag(&g_server_running);

            bool no_repl = result.count("no-repl") > 0;
            if (no_repl) {
                // -- Modo headless (sin REPL local) --
                vesta::scout() << "[server-mode] Pulse Ctrl+C o envie "
                                  "'server_shutdown' para detener.\n";
                while (g_server_running.load())
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } else {
                // -- REPL local compartiendo runtime con clientes remotos --
                //
                // El REPL (VestaViewManager) corre en ESTE thread porque
                // posee stdin (readline necesita TTY).  Un thread watcher
                // observa g_server_running: si el flag pasa a false desde
                // fuera (SIGINT o server_shutdown remoto), invoca
                // VestaViewManager::stop() para cerrar el bucle del REPL
                // -- pero como readline bloquea en stdin, el operador
                // debera pulsar Enter UNA vez para liberarlo.  Se imprime
                // un mensaje para que sepa que hacer.
                //
                // Cuando el operador local teclea 'exit' o EOF en el
                // REPL, vm.run() retorna; pasamos g_server_running a
                // false aqui mismo para que el watcher salga.
                vesta::scout() << "[server-mode] REPL local activo "
                                  "(teclea 'exit' o pulsa Ctrl+D para "
                                  "salir).  Tambien aceptamos "
                                  "'server_shutdown' del cliente.\n";

                cli::Config cfg_srv;
                cfg_srv.history_file = "my_vm_history.txt";
                cfg_srv.history_max = 1000;
                cfg_srv.prompt = "vesta(server)> ";
                cfg_srv.multiline_end = ";;";

                cli::VestaViewManager view_mgr(cfg_srv);
                view_mgr.set_execute_callback([](const std::string &cmd) {
                    // mismo comportamiento del REPL normal: ejecucion
                    // asincrona via run_command_async; cuando el future
                    // resuelve, se imprime el output.
                    auto fut = runtime::run_command_async(cmd);
                    std::thread([f = std::move(fut)]() mutable {
                        try {
                            auto out = f.get();
                            if (!out.empty())
                                vesta::scout() << out << std::endl;
                        } catch (const std::exception &e) {
                            std::cerr << "Runtime error: " << e.what()
                                      << std::endl;
                        }
                    }).detach();
                });

                std::atomic<bool> watcher_done{false};
                std::thread watcher([&]() {
                    while (g_server_running.load() && !watcher_done.load())
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(100));
                    if (watcher_done.load()) return;
                    // shutdown remoto / SIGINT: detener el REPL.  El
                    // readline poll-loop chequea I.running cada ~50 ms,
                    // asi que view_mgr.stop() liberara el prompt en
                    // ~50 ms sin requerir entrada del operador.
                    vesta::scout() << "\n[server-mode] Apagado recibido; "
                                      "cerrando REPL local.\n";
                    view_mgr.stop();
                });

                // Bucle del REPL (bloqueante en stdin).
                view_mgr.run();

                // El REPL salio (exit/EOF) o fue parado por el watcher;
                // marcar global y joinar el thread.
                g_server_running.store(false);
                watcher_done.store(true);
                if (watcher.joinable()) watcher.join();
            }

            vesta::scout() << "[server-mode] Senial de parada recibida; "
                              "deteniendo VM...\n";
            if (vm->dist_runtime) vm->dist_runtime->stop();
            dbg->stop();
            // Desconectar el hook ANTES de destruir la VM para que un
            // comando server_shutdown tardio no escriba a memoria liberada.
            debug::set_server_shutdown_flag(nullptr);
            vm->stop();
            vesta::scout() << "[server-mode] Servidor detenido.\n";
        } catch (const std::exception &e) {
            std::cerr << "[server-mode] Error: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Compilar un archivo como worker
    // vm.exe --worker src/main.vel -o main.velb
    if (result.count("worker")) {
        return asm_multi_process::run_worker(
            result["worker"].as<std::string>(), out_prefix,
            /*skip_preprocessor=*/false,
            /*keep_labels=*/(result.count("keep-labels") > 0),
            /*ir_section_bytes=*/nullptr,
            /*emit_map=*/(result.count("emit-map") > 0));
    }

    // Compilar un proyecto entero en paralelo
    // vm.exe --driver src/ -j 8 -o program.velb
    // Compilar con número automático de hilos
    // vm.exe --driver src/ -j 0 -o program.velb
    if (result.count("driver")) {
        int threads = result["threads"].as<int>();
        return asm_multi_process::run_driver(result["driver"].as<std::string>(),
                                             threads, out_prefix);
    }

    bool save_output = result.count("save-output") > 0;

    // ensamblar un solo archivo (modo clásico)
    // vm.exe --asm-file src/main.asm --arch x86_64
    if (result.count("asm-file")) {
        return assemble_file(result["asm-file"].as<std::string>(),
                             result["arch"].as<std::string>(), save_output,
                             out_prefix)
                   ? EXIT_SUCCESS
                   : EXIT_FAILURE;
    }

    if (result.count("disasm-file")) {
        // Un `.velb` lleva bytecode de la VM, no codigo del anfitrion:
        // desensamblarlo con el desensamblador nativo devuelve basura con
        // aspecto de instrucciones x86.  Se reconoce por su firma, asi que el
        // desensamblador se elige por el CONTENIDO del fichero y no por lo que
        // el usuario acierte a escribir -- y `--arch`, que ahi no significa
        // nada, deja de exigirse.
        const std::string dfile = result["disasm-file"].as<std::string>();
        {
            std::ifstream probe(dfile, std::ios::binary);
            char sig[4] = {0, 0, 0, 0};
            if (probe.read(sig, 4) && (std::memcmp(sig, "VELB", 4) == 0 ||
                                       std::memcmp(sig, "BLEV", 4) == 0)) {
                probe.close();
                // Volcar el fichero ENTERO: el `hlt` termina una funcion, no
                // el codigo, y pararse en el primero deja fuera todo lo demas
                // -- justo lo que hace falta cuando se compara el resultado de
                // enlazar varios modulos.
                disasm::DisasmOptions dopts;
                dopts.stop_at_hlt = false;
                disasm::disasm_velb(dfile, std::cout, dopts);
                return EXIT_SUCCESS;
            }
        }
        if (!result.count("arch")) {
            std::cerr << "--arch es requerido para desensamblar\n";
            return EXIT_FAILURE;
        }
        return disassemble_file(result["disasm-file"].as<std::string>(),
                                result["arch"].as<std::string>(), save_output,
                                out_prefix)
                   ? EXIT_SUCCESS
                   : EXIT_FAILURE;
    }

    // Compilar un archivo .ir (SSA IR) a .vel y opcionalmente a .velb
    // vm.exe --ir-file program.ir --ir-opt 2 -o program.velb
    if (result.count("ir-file")) {
        const std::string &ir_path = result["ir-file"].as<std::string>();
        int opt_n = result["ir-opt"].as<int>();
        bool emit_only = result.count("ir-emit-only") > 0;

        // Leer el archivo .ir
        std::ifstream ifs(ir_path);
        if (!ifs.is_open()) {
            std::cerr << "[ir] No se puede abrir: " << ir_path << "\n";
            return EXIT_FAILURE;
        }
        std::string ir_text((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());

        // Emitir .vel
        ir::EmitOptions eopts;
        eopts.opt_level = ir::opt_level_from_int(opt_n);
        eopts.emit_comments = true;
        eopts.export_all = true;

        ir::EmitResult er = ir::ir_emit_text(ir_text, eopts);
        if (!er.ok) {
            std::cerr << "[ir] Error de emision: " << er.error << "\n";
            return EXIT_FAILURE;
        }

        // Determinar nombre del archivo .vel de salida
        std::string vel_path =
            out_prefix.empty() ? "out.vel" : out_prefix + ".vel";
        {
            std::ofstream ofs(vel_path);
            if (!ofs.is_open()) {
                std::cerr << "[ir] No se puede escribir: " << vel_path << "\n";
                return EXIT_FAILURE;
            }
            ofs << er.vel_text;
        }
        vesta::scout() << "[ir] .vel generado: " << vel_path << "\n";

        if (emit_only) return EXIT_SUCCESS;

        // Compilar el .vel generado a .velb usando el pipeline existente
        return asm_multi_process::run_worker(
            vel_path, out_prefix,
            /*skip_preprocessor=*/false,
            /*keep_labels=*/(result.count("keep-labels") > 0),
            /*ir_section_bytes=*/nullptr,
            /*emit_map=*/(result.count("emit-map") > 0));
    }

    // Compilar un archivo .vx (lenguaje Vesta) a .velb.
    // Pipeline:
    //   .vx source
    //     -> [VPP opcional]    (metaprogramacion compartida con .vel)
    //     -> Vesta frontend      (lex + parse + tipos + lowering)
    //     -> ir::IrModule
    //     -> ir_emit_module    (texto .vel)
    //     -> run_worker(.vel, skip_preprocessor=true)
    //     -> .velb
    //
    // -----------------------------------------------------------------
    // Subsistema de coste (MODO ANALISIS): vm --analyze <archivo.vx>
    //
    // Rama APARTE del path de compilacion normal.  Compila el .vx hasta
    // el SSA IR (sin emitir .velb), corre el analizador estatico de
    // complejidad (analyze::bigo) sobre cada funcion del modulo OPTIMIZADO
    // (O2), e imprime el coste Big-O.  Si una funcion declara @complexity,
    // valida el contrato de forma conservadora (solo avisa si esta
    // CONFIADO de la discrepancia).  Cero impacto en el codegen.
    //
    //   vm --analyze prog.vx            -> salida legible
    //   vm --analyze prog.vx --analyze-json -> JSON (para diagramas)
    // -----------------------------------------------------------------
    // -----------------------------------------------------------------
    // VOLCADO DEL ASA: vm --asa <archivo.vx>
    //
    // Ensena lo que el compilador SABE del programa: cada afirmacion con su
    // dominio, su certeza y sobre que se dedujo, y ademas los SILENCIOS -- lo
    // que se miro sin sacar nada --, que es donde hay sitio para saber mas.
    //
    // No decide ni transforma: es la ventana a la base de hechos.  Sirve para
    // depurar un analisis que miente, para ver por que un consumidor renuncia,
    // y para saber que dominio hace falta antes de escribirlo.
    // -----------------------------------------------------------------
    if (result.count("asa")) {
        const std::string vx_path = result["asa"].as<std::string>();
        std::string vx_source;
        if (!vx::leer_fuente(vx_path, vx_source)) {
            std::cerr << "[asa] No se puede abrir: " << vx_path << "\n";
            return EXIT_FAILURE;
        }
        /* Se mira el codigo que de verdad va a existir (POST-O2), no el
         * escrito: lo que un consumidor consulta es esto. */
        vx::CompileOptions copts;
        copts.module_name = "main";
        copts.opt_level = 2;
        copts.ir_only = true;
        copts.report_bounds = false;
        /* Tambien el modulo de ANTES de optimizar.  Es la mitad que faltaba:
         * lo que el programa DICE y lo que va a EJECUTARSE no son lo mismo, y
         * entre los dos esta el optimizador.  Un `for` de 64 vueltas que el
         * desenrollador convierte en cuatro de dieciseis salia aqui como "no
         * se puede afirmar cuantas vueltas da" -- el conocimiento existia y se
         * habia destruido antes de que nadie lo publicara. */
        copts.emit_ir_preopt = true;
        const bool como_proyecto = vx::vx_source_has_imports(vx_source) ||
                                   vx::vx_source_declara_namespace(vx_source);
        vx::CompileResult cr =
            como_proyecto ? vx::compile_vx_project(vx_path, copts)
                          : vx::compile_vx_source(vx_source, vx_path, copts);
        for (const auto &d : cr.diagnostics.all())
            vx::print_diagnostic(std::cerr, d);
        if (!cr.ok || cr.ir_module_cache_bytes.empty()) {
            std::cerr << "[asa] la compilacion no dejo IR que mirar.\n";
            return EXIT_FAILURE;
        }
        ir::IrModule asa_mod;
        if (!ir::parse_ir_module_cache(cr.ir_module_cache_bytes, asa_mod)) {
            std::cerr << "[asa] no se pudo leer el IR.\n";
            return EXIT_FAILURE;
        }

        /* El asm es un dominio mas, pero su productor vive junto a la base de
         * datos de instrucciones: se da de alta desde aqui, que es quien la
         * tiene.  Para eso existe el registro. */
        analyze::register_asm_producer();
        /* Y el de la huella, por lo mismo: necesita la maquinaria de efectos,
         * que tampoco esta en el nucleo. */
        analyze::register_fingerprint_producer();

        analysis::asa::FactStore almacen;
        std::vector<analysis::asa::ProductionSummary> resumenes;

        /* PRIMERO lo que el programa dice, y solo despues lo que va a
         * ejecutarse.  El orden no es estetico: el ASA es donde vive lo que el
         * compilador sabe, asi que mirar solo despues de optimizar deja que
         * alguien opine sobre el programa antes que la capa que existe para no
         * tener que opinar -- y peor, destruye lo que iba a publicarse.
         *
         * Los dos van al MISMO almacen, cada hecho sellado con su momento: no
         * se contradicen, hablan de codigos distintos.  Ver la diferencia es
         * justo lo util -- "esto lo escribiste asi y acaba siendo asa otra
         * cosa" --, y colapsarlas obligaria a elegir una y a callar la otra. */
        ir::IrModule asa_mod_pre;
        if (!cr.ir_module_cache_bytes_preopt.empty() &&
            ir::parse_ir_module_cache(cr.ir_module_cache_bytes_preopt,
                                      asa_mod_pre)) {
            const auto pre = analysis::asa::produce(
                asa_mod_pre, almacen, {}, analysis::asa::kStagePreOpt);
            resumenes.insert(resumenes.end(), pre.begin(), pre.end());
        }
        const auto post = analysis::asa::produce(asa_mod, almacen, {},
                                                 analysis::asa::kStagePostOpt);
        resumenes.insert(resumenes.end(), post.begin(), post.end());
        analysis::asa::print_dump(almacen, resumenes, stdout);
        return EXIT_SUCCESS;
    }

    if (result.count("analyze")) {
        const std::string &vx_path = result["analyze"].as<std::string>();
        const bool want_json = result.count("analyze-json") > 0;

        /* Objetivo del ANALISIS.  Se elige igual que el de la compilacion
         * nativa (`--format` da el sistema, `--aot-arch` la arquitectura),
         * porque este compilador CRUZA: genera un ELF de Linux desde Windows.
         *
         * Sin esto, analizar solo valia para el anfitrion, y el codigo de la
         * otra plataforma -- justo el que uno quiere revisar sin poder
         * ejecutarlo -- ni siquiera compilaba: un
         * `@Target("arch:x86_64 && !os:windows")` se excluye, y lo que ese
         * import traia (en `std.syscall.linux`, la implementacion entera del
         * arch) quedaba sin declarar. */
        analysis::effects::Backend analyze_backend =
            analysis::effects::Backend::Vm;
        if (result.count("format") || result.count("aot-arch")) {
            const std::string fmt = result.count("format")
                                        ? result["format"].as<std::string>()
                                        : std::string();
            const std::string arch = result.count("aot-arch")
                                         ? result["aot-arch"].as<std::string>()
                                         : std::string("x86-64");
            std::string os_obj;
            if (fmt == "pe")
                os_obj = "windows";
            else if (fmt == "elf")
                os_obj = "linux";
            else {
#if defined(_WIN32)
                os_obj = "windows";
#else
                os_obj = "linux";
#endif
            }
            // Misma traduccion que arriba, por el mismo motivo.
            vx::set_aot_condcomp_target(os_obj,
                                        vx::cwhen::normalize_arch(arch));
            /* Pedir un objetivo nativo tambien cambia QUIEN ejecuta: alli las
             * ops que dependen del runtime son llamadas a libvesta_rt, y varias
             * ni existen.  El informe de efectos tiene que hablar de ese. */
            analyze_backend = analysis::effects::Backend::Aot;
        }

        std::string vx_source;
        if (!vx::leer_fuente(vx_path, vx_source)) {
            std::cerr << "[analyze] No se puede abrir: " << vx_path << "\n";
            return EXIT_FAILURE;
        }

        // Compilar hasta el IR.  Reutilizamos compile_vx_source que ya
        // rellena ir_module_cache_bytes (modulo POST-O2) y, con
        // @c emit_ir_preopt, tambien ir_module_cache_bytes_preopt
        // (modulo PRE-opt: la complejidad algoritmica del fuente).
        vx::CompileOptions copts;
        copts.module_name = "main";
        copts.opt_level = 2;
        copts.emit_ir_preopt = true;
        /* Y ademas el modulo con el inline puesto: el informe necesita los DOS
         * -- el cuerpo escrito para el coste, el codigo real para todo lo
         * demas -- y antes eso eran dos compilaciones del fuente entero. */
        copts.emit_ir_inlined = true;
        /* El informe lee IR y nada mas: el texto `.vel` se generaba entero --
         * asignacion de registros incluida, que es el noventa por ciento del
         * coste del frontend -- para tirarlo sin abrirlo. */
        copts.ir_only = true;
        // --analyze respeta -ffp-contract=off (el coste/IR reflejado debe
        // coincidir con el binario que se generara).
        copts.fp_contract =
            !(result.count("ffp-contract") &&
              result["ffp-contract"].as<std::string>() == "off");
        /* Analizar PARA nativo es analizar el programa que va a existir alli,
         * y ese no se parece al de la VM: el frontend baja distinto con POO
         * nativa (sin ClassInfo, sin handles, y con las primitivas de I/O como
         * simbolos en vez de opcodes).  Sin esto el informe describia la bajada
         * de la VM con la etiqueta de AOT encima. */
        copts.native_poo = (analyze_backend == analysis::effects::Backend::Aot);
        /* Los limites los ENSEÑA el informe, con su prueba; convertirlos en
         * error aqui dejaria sin analisis al programa que mas lo necesita. */
        copts.report_bounds = false;
        // Si el fuente tiene `import`, hay que ir por el compilador
        // multi-modulo, igual que hacen las demas rutas.  ANTES esta llamaba
        // siempre a `compile_vx_source` (un solo fichero), asi que analizar un
        // programa que importa cualquier cosa -- la stdlib incluida -- moria en
        // "funcion no declarada" en vez de darte el analisis.
        // Y tambien si DECLARA un namespace, aunque no importe nada: un
        // namespace puede repartirse entre varios ficheros (el base y uno por
        // arquitectura), y suelto no se sostiene porque usa lo que declaran sus
        // hermanos.  Con el criterio antiguo, analizar `std/types.vx` -- la
        // base de tipos de la que depende media stdlib -- moria en "tipo no
        // resuelto en alias".
        const bool como_proyecto = vx::vx_source_has_imports(vx_source) ||
                                   vx::vx_source_declara_namespace(vx_source);
        /* Cuanto cuesta analizar, por partes.  Hacia falta: la pregunta de por
         * que tarda solo se podia responder midiendo por fuera y suponiendo, y
         * suponer fallo -- la sospecha era la emision del `.vel` y no era.
         * Se pide con VESTA_TIMES para no ensuciar el informe. */
        using RelojAnalisis = std::chrono::steady_clock;
        auto marca_an = RelojAnalisis::now();
        auto tramo_us = [&marca_an]() -> long {
            const auto ahora = RelojAnalisis::now();
            const long us = static_cast<long>(
                std::chrono::duration_cast<std::chrono::microseconds>(ahora -
                                                                      marca_an)
                    .count());
            marca_an = ahora;
            return us;
        };
        const bool medir_analisis = util::flag_on(util::FlagId::Times);
        long us_compilar_coste = 0, us_modulo_final = 0;
        vx::CompileResult cr =
            como_proyecto ? vx::compile_vx_project(vx_path, copts)
                          : vx::compile_vx_source(vx_source, vx_path, copts);
        /* Y si hay codigo que se GENERA al compilar, se vuelve a compilar con
         * la maquina de compilacion cargada -- igual que hace el compilador.
         * Sin esto el informe describia los bloques de asm VACIOS: una funcion
         * que escribe sesenta y cuatro bytes por su parametro salia tocando
         * solo el hueco de una variable.  Un informe que habla de otro programa
         * no sirve para lo que existe: ver si el compilador entendio bien. */
        {
            std::error_code ec;
            const std::string tmp_pref =
                (std::filesystem::temp_directory_path(ec) /
                 ("vx_analyze_" +
                  std::filesystem::path(vx_path).stem().string()))
                    .string();
            recompilar_con_maquina_de_compilacion(cr, vx_path, vx_source, copts,
                                                  tmp_pref);
        }
        us_compilar_coste = tramo_us();
        // Volcar diagnosticos (errores/warnings) del frontend.
        for (const auto &d : cr.diagnostics.all())
            vx::print_diagnostic(std::cerr, d);
        if (!cr.ok) {
            std::cerr << "[analyze] la compilacion fallo; no hay IR que "
                         "analizar.\n";
            return EXIT_FAILURE;
        }
        if (cr.ir_module_cache_bytes.empty()) {
            std::cerr << "[analyze] el modulo no produjo IR.\n";
            return EXIT_FAILURE;
        }

        // Deserializar el modulo POST-opt (complejidad efectiva del codigo
        // final, tras inline/loop-elim/unroll) + correr el analisis +
        // composicion interprocedural (call-graph bottom-up -> coste TOTAL).
        ir::IrModule amod_post;
        if (!ir::parse_ir_module_cache(cr.ir_module_cache_bytes, amod_post)) {
            std::cerr << "[analyze] no se pudo deserializar el IR.\n";
            return EXIT_FAILURE;
        }
        /* En nativo, las primitivas de I/O no son codigo ajeno: el enlace se
         * trae `stdlib/vx/vx_io.vx` y sus CALLN acaban llamando a esas
         * funciones, escritas en Vesta.  Analizar sin ellas las daria por
         * opacas -- justo lo contrario de lo que pasa alli --, asi que se
         * traen tambien aqui.
         *
         * Cuando hacen falta se deduce del IR (quedan CALLN a un simbolo que
         * ninguna funcion del modulo define), no copiando la condicion del
         * enlazador: dos criterios para lo mismo se separan a la primera. */
        if (analyze_backend == analysis::effects::Backend::Aot) {
            std::unordered_set<std::string> definidas;
            for (const auto &f : amod_post.functions)
                definidas.insert(f.name);
            bool falta = false;
            for (const auto &f : amod_post.functions)
                for (const auto &b : f.blocks)
                    for (const auto &in : b.instrs) {
                        if (in.op != ir::IrOp::CALLN) continue;
                        const size_t sep = in.func_name.rfind(':');
                        if (sep == std::string::npos) continue;
                        if (!definidas.count(in.func_name.substr(sep + 1)))
                            falta = true;
                    }
            if (falta) {
                const std::string exe_dir =
                    std::filesystem::path(fs::get_executable_path())
                        .parent_path()
                        .string();
                for (const std::string &c :
                     {exe_dir + "/stdlib/vx/vx_io.vx",
                      exe_dir + "/../stdlib/vx/vx_io.vx",
                      std::string("stdlib/vx/vx_io.vx")}) {
                    if (!std::filesystem::exists(c)) continue;
                    vx::CompileOptions io_opts;
                    io_opts.module_name = "vx_io";
                    io_opts.opt_level = copts.opt_level;
                    io_opts.native_poo = true;
                    io_opts.asm_target_bits = copts.asm_target_bits;
                    vx::CompileResult io_cr =
                        vx::compile_vx_project(c, io_opts);
                    ir::IrModule io_mod;
                    if (io_cr.ok && !io_cr.ir_module_cache_bytes.empty() &&
                        ir::parse_ir_module_cache(io_cr.ir_module_cache_bytes,
                                                  io_mod)) {
                        for (auto &f : io_mod.functions)
                            if (!definidas.count(f.name))
                                amod_post.functions.push_back(std::move(f));
                        for (auto &ni : io_mod.native_imports)
                            amod_post.register_native_import(ni.lib, ni.name,
                                                             ni.effects);
                    }
                    break;
                }
            }
        }
        analyze::ModuleCost mc_post = analyze::analyze_module(amod_post);
        analyze::compose_interproc(mc_post);

        // Huella computacional (recursos + efectos) sobre el modulo POST-opt +
        // composicion interprocedural.  Complementa el coste Big-O con
        // propiedades EXACTAS/sound: allocs, stack, pure, throws, panics,
        // recursion.  Es tambien el resumen del codegen dirigido por resumenes.
        auto fps_post = analyze::compute_module_fingerprints(amod_post);
        // Pasar los contratos: las fn de marco opaco (`asm { }`) aportan su
        // @stack DECLARADO al total de sus callers (su frame real no se ve).
        analyze::compose_fingerprints(fps_post, &cr.contracts);

        /* Modelo UNICO de efectos.  Corre sobre el modulo COMO SE COMPILA, que
         * NO es el de arriba: `--analyze` optimiza sin inline a proposito (el
         * coste PARCIAL tiene que ser el del cuerpo escrito, no el del cuerpo
         * mas lo que le metieron dentro), y eso vale para medir coste pero
         * MIENTE para el resto.
         *
         * Se noto midiendo: el comprobador de limites daba CERO avisos aqui y
         * DIECISIETE al compilar los mismos programas.  Una herramienta de
         * analisis que describe un programa distinto del que se construye es
         * peor que no tenerla, porque se le cree.
         *
         * Asi que se pide TAMBIEN el modulo con el inline puesto.  Sale de la
         * misma bajada -- basta optimizar una copia --, asi que ya no cuesta
         * una compilacion entera del fuente como cuando eran dos pasadas
         * separadas: en un fuente pequeno con codigo generado al compilar, esa
         * segunda pasada era casi la mitad de lo que tardaba el informe. */
        const long us_coste_bigo = tramo_us();
        ir::IrModule amod_build;
        bool hay_build = false;
        if (!cr.ir_module_cache_bytes_inlined.empty())
            hay_build = ir::parse_ir_module_cache(
                cr.ir_module_cache_bytes_inlined, amod_build);
        us_modulo_final = tramo_us();
        const ir::IrModule &amod_efectos = hay_build ? amod_build : amod_post;
        if (!want_json)
            /* Los DOS estados: antes de optimizar y el codigo final.  Mirar
             * solo uno describe una parte del programa. */
            analysis::effects::print_effects_report(
                std::cout, amod_efectos, analyze_backend,
                hay_build ? &amod_post : nullptr);
        auto find_fp = [&](const std::string &name)
            -> const analyze::FunctionFingerprint * {
            for (const auto &f : fps_post)
                if (f.function == name) return &f;
            return nullptr;
        };

        // Procedencia generica (contrato B.3): que instanciaciones vienen del
        // mismo template.  `atomic_i64__fetch_add` y `atomic_f64__fetch_add`
        // son funciones distintas del IR, pero las dos salen de
        // `atomic<T>::fetch_add`; agruparlas es lo que permite reportar (y
        // sugerir) el coste POR TIPO -- "O(1) si is_integer<T>, O(n) si
        // is_float<T>" -- en vez de dos lineas sueltas.
        struct GenOrigen {
            std::string plantilla;              // "atomic"
            std::vector<std::string> type_args; // {"i64"}
            std::string metodo;                 // "fetch_add"
        };
        std::map<std::string, GenOrigen> origen; // nombre mangled -> origen
        for (const auto &f : amod_post.functions) {
            if (f.generic_template_name.empty()) continue;
            GenOrigen g;
            g.plantilla = f.generic_template_name;
            g.type_args = f.generic_type_args;
            // El metodo es lo que queda al quitar el prefijo
            // `<plantilla>_<join(type_args,"_")>__`.  Asi
            // `atomic_i64____deref__` (prefijo `atomic_i64__`) deja
            // `__deref__`.
            std::string pref = f.generic_template_name;
            for (const auto &t : f.generic_type_args)
                pref += "_" + t;
            pref += "__";
            if (f.name.size() > pref.size() &&
                f.name.compare(0, pref.size(), pref) == 0)
                g.metodo = f.name.substr(pref.size());
            else
                g.metodo = f.name; // fallback: no casa el mangle esperado
            origen[f.name] = std::move(g);
        }
        // La clase de un type-arg, para elegir el predicado del `when:`.
        auto clase_tipo = [](const std::string &t) -> std::string {
            if (t.size() >= 2 && (t[0] == 'i' || t[0] == 'u') &&
                std::isdigit(static_cast<unsigned char>(t[1])))
                return "integer";
            if (t == "f32" || t == "f64") return "float";
            if (!t.empty() &&
                (t.back() == '*' || t.find("ptr") != std::string::npos))
                return "pointer";
            return "otro";
        };
        // Contratos de huella (@pure/@nothrow/@nopanic/@alloc/@stack)
        // declarados por el usuario, verificados contra la huella inferida.
        auto contract_checks =
            analyze::verify_contracts(fps_post, cr.contracts);

        // Deserializar el modulo PRE-opt (complejidad algoritmica del fuente
        // tal como se escribio).  Si por alguna razon no esta disponible,
        // caemos al post (mejor mostrar algo que fallar).
        bool have_pre = !cr.ir_module_cache_bytes_preopt.empty();
        ir::IrModule amod_pre;
        analyze::ModuleCost mc_pre;
        if (have_pre && ir::parse_ir_module_cache(
                            cr.ir_module_cache_bytes_preopt, amod_pre)) {
            mc_pre = analyze::analyze_module(amod_pre);
            analyze::compose_interproc(mc_pre);
        } else {
            have_pre = false;
        }

        // Helper: localizar el CostResult de una funcion por nombre en un
        // ModuleCost (el orden pre/post puede diferir tras la optimizacion).
        auto find_fn =
            [](const analyze::ModuleCost &m,
               const std::string &name) -> const analyze::CostResult * {
            for (const auto &f : m.functions)
                if (f.function == name) return &f;
            return nullptr;
        };

        // Helper: validar UNA dimension declarada contra su clase inferida.
        // CONSERVADOR: solo senala discrepancia si HAY contrato, la
        // inferencia es EXACT, ambas clases son conocidas (no O(?)) y
        // difieren.  Devuelve true si hay discrepancia confirmada.  Si la
        // dimension no se declara (decl vacio) devuelve false sin tocar nada.
        auto validate_dim = [](const std::string &decl,
                               analyze::CostClass inferred,
                               analyze::Confidence conf) -> bool {
            if (decl.empty()) return false;
            analyze::CostClass dc = analyze::parse_cost_class(decl);
            if (conf != analyze::Confidence::EXACT) return false;
            if (inferred == analyze::CostClass::O_UNKNOWN) return false;
            if (dc == analyze::CostClass::O_UNKNOWN) return false;
            return dc != inferred;
        };

        if (want_json) {
            // JSON: coste (pre/post) + huella (recursos/efectos) + contratos.
            auto jstr = [](const std::string &s) {
                std::string o;
                for (char c : s) {
                    if (c == '"' || c == '\\') o.push_back('\\');
                    o.push_back(c);
                }
                return o;
            };
            std::ostringstream js;
            js << "{\"pre\":"
               << (have_pre ? analyze::module_cost_to_json(mc_pre)
                            : std::string("[]"))
               << ",\"post\":" << analyze::module_cost_to_json(mc_post);
            // Huella por funcion.
            js << ",\"fingerprint\":[";
            for (size_t i = 0; i < fps_post.size(); ++i) {
                const auto &f = fps_post[i];
                if (i) js << ",";
                js << "{\"function\":\"" << jstr(f.function)
                   << "\",\"allocs\":" << f.alloc_sites_total
                   << ",\"stack\":" << f.stack_bytes
                   << ",\"pure\":" << (f.pure ? "true" : "false")
                   << ",\"throws\":" << (f.throws_total ? "true" : "false")
                   << ",\"panics\":" << (f.panics_total ? "true" : "false")
                   << ",\"recursion\":" << (f.recursive ? "true" : "false")
                   << ",\"effects_known\":"
                   << (f.effects_known ? "true" : "false") << "}";
            }
            js << "]";
            // Contratos verificados.
            js << ",\"contracts\":[";
            for (size_t i = 0; i < contract_checks.size(); ++i) {
                const auto &ck = contract_checks[i];
                if (i) js << ",";
                const char *st = ck.status == analyze::ContractCheck::OK ? "ok"
                                 : ck.status == analyze::ContractCheck::VIOLATED
                                     ? "violated"
                                     : "unverifiable";
                js << "{\"function\":\"" << jstr(ck.function)
                   << "\",\"contract\":\"" << jstr(ck.contract)
                   << "\",\"status\":\"" << st << "\",\"detail\":\""
                   << jstr(ck.detail) << "\"}";
            }
            js << "]";
            // Modelo unico de efectos (mismo que --analyze legible + DCE): los
            // diagramas consumen exactamente lo que ve el compilador.
            js << ",\"effects\":";
            analysis::effects::effects_json(js, amod_post);
            js << "}";
            std::cout << js.str() << "\n";
            return EXIT_SUCCESS;
        }

        if (medir_analisis) {
            const long us_efectos = tramo_us();
            const auto &tf = cr.tiempos;
            std::cerr << "[analyze] tiempos: compilar " << us_compilar_coste
                      << " us | coste " << us_coste_bigo
                      << " us | modulo-final " << us_modulo_final
                      << " us | efectos " << us_efectos << " us\n";
            std::cerr << "[analyze]   dentro de compilar: resolver "
                      << tf.resolver_us << " us | modulos " << tf.modulos_us
                      << " us | analisis " << tf.analisis_us << " us | tipos "
                      << tf.tipos_us << " us | bajada " << tf.bajada_us
                      << " us | optimizar " << tf.optimizar_us << " us\n";
        }

        // Salida legible: por cada funcion (orden del modulo POST-opt),
        // mostrar los 4 costes: PRE/POST x PARCIAL/TOTAL.
        std::cout << "Analisis de coste (Big-O) -- " << vx_path << "\n";
        std::cout << "Niveles: PRE-opt (fuente) y POST-opt (codigo final O2);"
                     " PARCIAL (cuerpo, calls=O(1)) y TOTAL (interprocedural)."
                     "\n";
        std::cout << "Contrato @complexity: cada dimension declarada "
                     "(partial_pre/partial_post/total_pre/total_post) se valida"
                     " contra su coste inferido.  @complexity(O(...)) = azucar"
                     " de total_post.\n";
        std::cout << "=================================================="
                     "===========\n";
        int mismatches = 0;
        for (const auto &rp : mc_post.functions) {
            const analyze::CostResult *pre =
                have_pre ? find_fn(mc_pre, rp.function) : nullptr;

            std::cout << "  " << rp.function << "\n";
            // PRE-opt.
            if (pre) {
                std::cout << "      PRE-opt : parcial "
                          << analyze::cost_class_str(pre->big_o) << "   total "
                          << analyze::cost_class_str(pre->total_class) << "   ["
                          << pre->detail << "]\n";
            } else {
                std::cout << "      PRE-opt : (no disponible)\n";
            }
            // POST-opt.
            std::cout << "      POST-opt: parcial "
                      << analyze::cost_class_str(rp.big_o) << "   total "
                      << analyze::cost_class_str(rp.total_class) << "   ["
                      << rp.detail << "]\n";

            // Resaltar cuando PRE difiere de POST (el optimizer simplifico).
            if (pre && pre->total_class != rp.total_class) {
                std::cout << "      >> el optimizer cambio el coste TOTAL: "
                          << analyze::cost_class_str(pre->total_class)
                          << " (fuente) -> "
                          << analyze::cost_class_str(rp.total_class)
                          << " (efectivo)\n";
            }
            // Resaltar cuando PARCIAL difiere de TOTAL (callees elevan).
            if (rp.big_o != rp.total_class) {
                std::cout << "      >> callees elevan el coste: parcial "
                          << analyze::cost_class_str(rp.big_o) << " -> total "
                          << analyze::cost_class_str(rp.total_class) << "\n";
            }

            // Huella computacional (propiedades EXACTAS/sound).  allocs y stack
            // se muestran parcial/total (propio / cierre o pila peor caso).
            if (const auto *fp = find_fp(rp.function)) {
                const std::string st_tot =
                    fp->stack_bytes_total == analyze::STACK_UNBOUNDED
                        ? std::string("inf")
                        : std::to_string(fp->stack_bytes_total);
                std::cout << "      Huella  : allocs=" << fp->alloc_sites << "/"
                          << fp->alloc_sites_total
                          << " stack=" << fp->stack_bytes << "/" << st_tot
                          << "B"
                          << " (parcial/total)"
                          << " pure=" << (fp->pure ? "si" : "no")
                          << " throws=" << (fp->throws_total ? "si" : "no")
                          << " panics=" << (fp->panics_total ? "si" : "no")
                          << " recursion=" << (fp->recursive ? "si" : "no");
                if (!fp->effects_known)
                    std::cout << "  (efectos parcialmente desconocidos: "
                                 "llamada dinamica/externa)";
                std::cout << "\n";
            }

            // Contratos de huella declarados por el usuario para esta funcion.
            for (const auto &ck : contract_checks) {
                if (ck.function != rp.function) continue;
                const char *mark =
                    ck.status == analyze::ContractCheck::OK         ? "OK  "
                    : ck.status == analyze::ContractCheck::VIOLATED ? "FALLA"
                                                                    : "?   ";
                std::cout << "      " << mark << " " << ck.contract << " -> "
                          << ck.detail << "\n";
                if (ck.status == analyze::ContractCheck::VIOLATED) ++mismatches;
            }

            // Contrato @complexity: validar CADA dimension declarada contra
            // su coste inferido correspondiente.  Cada una es independiente.
            const bool has_any_contract =
                !rp.decl_partial_pre.empty() || !rp.decl_partial_post.empty() ||
                !rp.decl_total_pre.empty() || !rp.decl_total_post.empty();
            if (has_any_contract) {
                std::cout << "      @complexity declarada:\n";
                // Tabla: (etiqueta, decl, inferida, confianza).  Para PRE
                // usamos el CostResult PRE si existe.
                struct DimRow {
                    const char *label;
                    const std::string *decl;
                    analyze::CostClass inferred;
                    analyze::Confidence conf;
                    bool have;
                };
                std::vector<DimRow> rows = {
                    {"partial_pre ", &rp.decl_partial_pre,
                     pre ? pre->big_o : analyze::CostClass::O_UNKNOWN,
                     pre ? pre->confidence : analyze::Confidence::UNKNOWN,
                     pre != nullptr},
                    {"partial_post", &rp.decl_partial_post, rp.big_o,
                     rp.confidence, true},
                    {"total_pre   ", &rp.decl_total_pre,
                     pre ? pre->total_class : analyze::CostClass::O_UNKNOWN,
                     pre ? pre->total_confidence : analyze::Confidence::UNKNOWN,
                     pre != nullptr},
                    {"total_post  ", &rp.decl_total_post, rp.total_class,
                     rp.total_confidence, true},
                };
                for (const auto &row : rows) {
                    if (row.decl->empty()) continue;
                    std::cout << "        " << row.label << ": " << *row.decl
                              << " -> "
                              << analyze::cost_class_str(
                                     analyze::parse_cost_class(*row.decl));
                    if (!row.have) {
                        std::cout << "  (dimension no disponible; no validada)";
                    } else if (validate_dim(*row.decl, row.inferred,
                                            row.conf)) {
                        std::cout << "  ** DISCREPANCIA: inferida "
                                  << analyze::cost_class_str(row.inferred)
                                  << " **";
                        ++mismatches;
                    } else {
                        std::cout << "  (ok, inferida "
                                  << analyze::cost_class_str(row.inferred)
                                  << ")";
                    }
                    std::cout << "\n";
                }
            }
        }
        // Huella + contratos de TIPO (structs/clases/enums).  El layout de todo
        // struct es C-compatible por invariante del lenguaje; @pod indica
        // ademas que es trivialmente copiable (sin dtor ni campos gestionados).
        if (!cr.type_fingerprints.empty()) {
            auto type_checks = analyze::verify_type_contracts(
                cr.type_fingerprints, cr.type_contracts);
            std::cout << "\n--- Tipos ---\n";
            for (const auto &tf : cr.type_fingerprints) {
                const char *kind =
                    tf.kind == analyze::TypeFingerprint::STRUCT  ? "struct"
                    : tf.kind == analyze::TypeFingerprint::CLASS ? "class"
                                                                 : "enum";
                std::cout << "  " << kind << " " << tf.type_name
                          << " : size=" << tf.size_bytes << "B"
                          << " align=" << tf.align_bytes
                          << " fields=" << tf.field_count
                          << (tf.is_pod ? " [pod]" : "")
                          << (tf.no_heap ? " [no_heap]" : "")
                          << (tf.has_destructor ? " [~dtor]" : "")
                          << (tf.is_reference ? " [ref]" : "") << "\n";
                for (const auto &ck : type_checks) {
                    if (ck.function != tf.type_name) continue;
                    const char *st =
                        ck.status == analyze::ContractCheck::OK ? "OK  "
                        : ck.status == analyze::ContractCheck::VIOLATED
                            ? "FALLA"
                            : "????";
                    std::cout << "      " << st << " " << ck.contract << " -> "
                              << ck.detail << "\n";
                    if (ck.status == analyze::ContractCheck::VIOLATED)
                        ++mismatches;
                }
            }
        }
        // ------------------------------------------------------------------
        //  El coste POR ARQUITECTURA.
        //
        //  Todo lo de arriba es para el target del HOST.  Pero el coste TOTAL
        //  cambia con la arquitectura cuando algun callee tiene variantes
        //  @Target de cuerpos distintos -- `vx_atomic_swap64` es un bucle CAS
        //  en x86-64 (no hay instruccion de exchange) y el LL/SC nativo en
        //  arm64 --, asi que reportar solo el host enseña media foto.
        //
        //  Se recorre el registro CERRADO de arquitecturas, recompilando para
        //  cada una (@Target se evalua contra el target, no contra el host: es
        //  lo mismo que hace el driver AOT cross-target).  Solo se imprime lo
        //  que DIFIERE: si una funcion cuesta igual en todas -- el caso comun,
        //  y todo el fichero si no usa @Target -- no se dice nada y la salida
        //  queda como estaba.
        // ------------------------------------------------------------------
        {
            std::string host_os, host_arch;
            vx::get_aot_condcomp_target(host_os, host_arch);

            // arch -> (funcion -> resumen), o el motivo de no compilar.  El
            // resumen junta el coste Y la huella: las dos varian con la
            // arquitectura -- el coste cuando un callee tiene cuerpos por-arch
            // distintos, y la huella cuando el cuerpo si (los `register()` de
            // una variante @Target("arch:arm64") gastan frame que su gemela
            // x86-64 no), asi que las dos hay que reportarlas por arch.
            // Datos CRUDOS de una funcion en una arquitectura (no solo el
            // string resumen): --annotate los necesita desglosados para generar
            // cada anotacion y decidir si difiere entre arch.
            struct FnData {
                bool present = false;
                std::string partial_pre, partial_post, total_pre, total_post;
                // @alloc y @stack en DOS dimensiones: parcial (propio) y total
                // (cierre / pila peor caso).  stack_total = STACK_UNBOUNDED si
                // no acotable (recursion/externo).
                uint64_t alloc_partial = 0, alloc_total = 0;
                uint64_t stack_partial = 0, stack_total = 0;
                bool pure = false, throws = false, panics = false;
            };
            struct PorArch {
                std::string arch;
                std::map<std::string, std::string> resumen;
                std::map<std::string, FnData> datos;
                std::string fallo;
            };
            std::vector<PorArch> tabla;
            for (const auto &arch : vx::cwhen::known_archs()) {
                PorArch pa;
                pa.arch = arch;
                vx::set_aot_condcomp_target(host_os, arch);
                vx::CompileOptions o2;
                o2.module_name = "main";
                o2.opt_level = 2;
                // IGUAL que el analisis principal: pedir tambien el IR PRE-opt.
                // Sin esto, el POST se optimiza CON inline y el `partial`
                // cuenta el cuerpo inlineado -> mide distinto que verify (que
                // si usa el no-inline) y la sugerencia contradice la
                // verificacion.
                o2.emit_ir_preopt = true;
                /* Y de aqui tampoco se lee el texto `.vel`: esta tabla mira el
                 * IR de cada arquitectura y nada mas.  Compilar el fuente una
                 * vez por arquitectura ya cuesta; hacerlo generando ademas el
                 * codigo maquina de cada una para tirarlo era la mayor parte de
                 * lo que tardaba el informe en los fuentes grandes. */
                o2.ir_only = true;
                vx::CompileResult r2 =
                    vx::vx_source_has_imports(vx_source)
                        ? vx::compile_vx_project(vx_path, o2)
                        : vx::compile_vx_source(vx_source, vx_path, o2);
                if (!r2.ok || r2.ir_module_cache_bytes.empty()) {
                    // Que el fuente no compile para una arquitectura NO es un
                    // error del analisis: es justo lo que hay que decir (p.ej.
                    // los atomicos de 64 bits no tienen variante en x86-32).
                    pa.fallo = "no compila para esta arquitectura";
                    for (const auto &d : r2.diagnostics.all()) {
                        if (d.level == vx::DiagLevel::ERR) {
                            pa.fallo = d.message;
                            break;
                        }
                    }
                    tabla.push_back(std::move(pa));
                    continue;
                }
                // POST-opt (sin inline, gracias a emit_ir_preopt): el `partial`
                // es el cuerpo propio; el `total` lo compone el call-graph.
                ir::IrModule m2;
                if (!ir::parse_ir_module_cache(r2.ir_module_cache_bytes, m2)) {
                    pa.fallo = "no se pudo deserializar el IR";
                    tabla.push_back(std::move(pa));
                    continue;
                }
                analyze::ModuleCost c2 = analyze::analyze_module(m2);
                analyze::compose_interproc(c2);
                // PRE-opt (complejidad algoritmica del fuente).  Si falta, el
                // pre cae al post (mejor mostrar algo que fallar).
                ir::IrModule m2_pre;
                analyze::ModuleCost c2_pre;
                bool tiene_pre = !r2.ir_module_cache_bytes_preopt.empty() &&
                                 ir::parse_ir_module_cache(
                                     r2.ir_module_cache_bytes_preopt, m2_pre);
                if (tiene_pre) {
                    c2_pre = analyze::analyze_module(m2_pre);
                    analyze::compose_interproc(c2_pre);
                }
                auto find_c2 =
                    [](const analyze::ModuleCost &m,
                       const std::string &nm) -> const analyze::CostResult * {
                    for (const auto &f : m.functions)
                        if (f.function == nm) return &f;
                    return nullptr;
                };
                auto fp2 = analyze::compute_module_fingerprints(m2);
                analyze::compose_fingerprints(fp2, &r2.contracts);
                std::map<std::string, const analyze::FunctionFingerprint *> fpx;
                for (const auto &f : fp2)
                    fpx[f.function] = &f;
                for (const auto &f : c2.functions) {
                    // Las 4 dimensiones, IGUAL que el analisis principal:
                    //   partial_pre  = cuerpo propio, PRE-opt
                    //   partial_post = cuerpo propio, POST-opt (sin inline)
                    //   total_pre    = interproc, PRE-opt
                    //   total_post   = interproc, POST-opt
                    const analyze::CostResult *pre =
                        tiene_pre ? find_c2(c2_pre, f.function) : nullptr;
                    FnData fd;
                    fd.present = true;
                    fd.partial_pre =
                        analyze::cost_class_str(pre ? pre->big_o : f.big_o);
                    fd.partial_post = analyze::cost_class_str(f.big_o);
                    fd.total_pre = analyze::cost_class_str(
                        pre ? pre->total_class : f.total_class);
                    fd.total_post = analyze::cost_class_str(f.total_class);
                    std::string s = fd.partial_post + " / " + fd.total_post;
                    auto it = fpx.find(f.function);
                    if (it != fpx.end()) {
                        const auto *h = it->second;
                        fd.alloc_partial = h->alloc_sites;
                        fd.alloc_total = h->alloc_sites_total;
                        fd.stack_partial = h->stack_bytes;
                        fd.stack_total = h->stack_bytes_total;
                        fd.pure = h->pure;
                        fd.throws = h->throws_total;
                        fd.panics = h->panics_total;
                        const std::string st_tot =
                            h->stack_bytes_total == analyze::STACK_UNBOUNDED
                                ? std::string("inf")
                                : std::to_string(h->stack_bytes_total);
                        s += "  allocs=" + std::to_string(h->alloc_sites) +
                             "/" + std::to_string(h->alloc_sites_total) +
                             " stack=" + std::to_string(h->stack_bytes) + "/" +
                             st_tot + "B" + " pure=" + (h->pure ? "si" : "no") +
                             " throws=" + (h->throws_total ? "si" : "no") +
                             " panics=" + (h->panics_total ? "si" : "no");
                    }
                    pa.resumen[f.function] = std::move(s);
                    pa.datos[f.function] = std::move(fd);
                }
                tabla.push_back(std::move(pa));
            }
            vx::set_aot_condcomp_target(host_os,
                                        host_arch); // dejarlo como estaba
            if (medir_analisis)
                std::cerr << "[analyze] tiempos: por-arquitectura ("
                          << vx::cwhen::known_archs().size()
                          << " compilaciones) " << tramo_us() << " us\n";

            // Las funciones cuyo coste o huella NO son iguales en todas.
            std::set<std::string> difieren;
            for (const auto &f : mc_post.functions) {
                const std::string *ref = nullptr;
                for (const auto &pa : tabla) {
                    if (!pa.fallo.empty()) continue;
                    auto it = pa.resumen.find(f.function);
                    if (it == pa.resumen.end()) continue;
                    if (!ref)
                        ref = &it->second;
                    else if (*ref != it->second)
                        difieren.insert(f.function);
                }
            }
            std::vector<std::string> no_compilan;
            for (const auto &pa : tabla)
                if (!pa.fallo.empty())
                    no_compilan.push_back(pa.arch + ": " + pa.fallo);

            if (!difieren.empty() || !no_compilan.empty()) {
                std::cout
                    << "\nCoste y huella por arquitectura (parcial / total"
                       " POST-opt + allocs/stack/pure/throws/panics).  "
                       "Solo lo que difiere.\n";
                std::cout
                    << "=================================================="
                       "===========\n";
                for (const auto &fn : difieren) {
                    std::cout << "  " << fn << "\n";
                    for (const auto &pa : tabla) {
                        if (!pa.fallo.empty()) continue;
                        auto it = pa.resumen.find(fn);
                        if (it == pa.resumen.end()) continue;
                        std::cout << "      " << pa.arch;
                        for (size_t k = pa.arch.size(); k < 8; ++k)
                            std::cout << ' ';
                        std::cout << " " << it->second << "\n";
                    }
                }
                for (const auto &s : no_compilan)
                    std::cout << "  [aviso] " << s << "\n";
            }

            // --annotate: las anotaciones que cada funcion deberia llevar,
            // segun lo medido, con `when: arch:X` donde difieren.  Es lo que
            // el programador tendria que escribir a mano; aqui lo genera el
            // analizador (el valor ES lo que mide, no una suposicion).
            // Anotaciones sugeridas -- SIEMPRE con --analyze (no hay flag
            // aparte: analizar y decir que contrato deberia llevar cada funcion
            // es lo mismo).  Se emiten los contratos medidos, con el `when:`
            // MiNIMO que describe donde vale cada valor: por arquitectura,
            // por tipo (las instanciaciones de un generico se AGRUPAN bajo su
            // plantilla), o los dos ejes a la vez -- solapando donde el valor
            // coincide, sin perder informacion.
            {
                auto archs_ok = [&]() {
                    std::vector<const PorArch *> v;
                    for (const auto &pa : tabla)
                        if (pa.fallo.empty()) v.push_back(&pa);
                    return v;
                }();

                // Agrupar las funciones por su origen: las instanciaciones de
                // un mismo `plantilla::metodo` van juntas; las no genericas,
                // solas.
                std::vector<std::string> orden_grupos;
                std::map<std::string, std::vector<std::string>> instancias;
                std::map<std::string, std::string> display;
                for (const auto &f : mc_post.functions) {
                    std::string clave, disp;
                    auto it = origen.find(f.function);
                    if (it != origen.end()) {
                        clave = it->second.plantilla + "::" + it->second.metodo;
                        disp =
                            it->second.plantilla + "<T>::" + it->second.metodo;
                    } else {
                        clave = f.function;
                        disp = f.function;
                    }
                    if (!instancias.count(clave)) orden_grupos.push_back(clave);
                    instancias[clave].push_back(f.function);
                    display[clave] = disp;
                }

                // Una combinacion (arquitectura, clase-de-tipo) y su FnData.
                struct Combo {
                    std::string arch;
                    std::string tc; // "" si el grupo no es generico
                    const FnData *d;
                };

                // `when:` MiNIMO para el conjunto de combos que comparten un
                // valor, dado el universo de combos del grupo.  Casos, de mas
                // general a mas especifico:
                //   - cubre TODAS las combos           -> sin when;
                //   - todas las arch, un subconjunto de tipos -> solo
                //   is_X<T>();
                //   - un subconjunto de arch, todos los tipos -> solo arch:X;
                //   - resto -> OR de `arch:X && is_Y<T>()` por combo,
                //   factorizando
                //     por arch cuando ese arch tiene todos sus tipos.
                auto pred_tipo = [](const std::string &tc) {
                    return "is_" + tc + "<T>()";
                };
                auto when_de =
                    [&](const std::vector<const Combo *> &sel,
                        const std::set<std::string> &all_archs,
                        const std::set<std::string> &all_tcs) -> std::string {
                    const bool generico =
                        !(all_tcs.size() == 1 && all_tcs.count(""));
                    if (sel.size() == all_archs.size() * all_tcs.size())
                        return std::string(); // cubre todo
                    // Agrupar la seleccion por arch -> tipos.
                    std::map<std::string, std::set<std::string>> por_arch;
                    for (const auto *c : sel)
                        por_arch[c->arch].insert(c->tc);
                    // Todas las arch presentes con el MISMO subconjunto de
                    // tipos
                    // -> el eje arch no distingue; factorizar por tipo.
                    if (generico && por_arch.size() == all_archs.size()) {
                        bool iguales = true;
                        const auto &ref = por_arch.begin()->second;
                        for (const auto &kv : por_arch)
                            if (kv.second != ref) {
                                iguales = false;
                                break;
                            }
                        if (iguales) {
                            std::string w;
                            bool first = true;
                            for (const auto &tc : ref) {
                                if (!first) w += " || ";
                                w += pred_tipo(tc);
                                first = false;
                            }
                            return ", when: " + w;
                        }
                    }
                    // OR de terminos, uno por arch (factorizando el tipo si ese
                    // arch tiene TODOS los tipos).
                    std::string w;
                    bool first = true;
                    for (const auto &kv : por_arch) {
                        const bool todos_tc =
                            !generico || kv.second.size() == all_tcs.size();
                        if (todos_tc) {
                            if (!first) w += " || ";
                            w += "arch:" + kv.first;
                            first = false;
                        } else {
                            for (const auto &tc : kv.second) {
                                if (!first) w += " || ";
                                w +=
                                    "arch:" + kv.first + " && " + pred_tipo(tc);
                                first = false;
                            }
                        }
                    }
                    return ", when: " + w;
                };

                // Para cada grupo, las lineas de anotacion (sin indentacion ni
                // el comentario `//`), en un vector reutilizable: se imprimen a
                // stdout Y, con --analyze-write, se insertan en el fichero.
                std::map<std::string, std::vector<std::string>> anot_por_clave;
                for (const auto &clave : orden_grupos) {
                    std::vector<Combo> combos;
                    std::set<std::string> all_archs, all_tcs;
                    for (const auto &inst : instancias[clave]) {
                        std::string tc;
                        auto ito = origen.find(inst);
                        if (ito != origen.end() &&
                            !ito->second.type_args.empty())
                            tc = clase_tipo(ito->second.type_args[0]);
                        all_tcs.insert(tc);
                        for (const auto *pa : archs_ok) {
                            auto it = pa->datos.find(inst);
                            if (it == pa->datos.end() || !it->second.present)
                                continue;
                            combos.push_back({pa->arch, tc, &it->second});
                            all_archs.insert(pa->arch);
                        }
                    }
                    if (combos.empty()) continue;

                    std::vector<std::string>
                        lineas; // "@nothrow", "@stack(...)"...

                    auto emitir = [&](const std::function<std::string(
                                          const FnData &)> &get,
                                      const std::function<std::string(
                                          const std::string &,
                                          const std::string &)> &render) {
                        std::map<std::string, std::vector<const Combo *>> porv;
                        for (const auto &c : combos)
                            porv[get(*c.d)].push_back(&c);
                        for (const auto &kv : porv)
                            lineas.push_back(
                                render(kv.first,
                                       when_de(kv.second, all_archs, all_tcs)));
                    };

                    // Flags (@pure/@nothrow/@nopanic): donde la prop se CUMPLE.
                    auto flag =
                        [&](const char *nombre,
                            const std::function<bool(const FnData &)> &p) {
                            std::vector<const Combo *> sel;
                            for (const auto &c : combos)
                                if (p(*c.d)) sel.push_back(&c);
                            if (sel.empty()) return;
                            std::string w = when_de(sel, all_archs, all_tcs);
                            if (w.empty())
                                lineas.push_back(std::string("@") + nombre);
                            else // el flag no lleva N: `, when:` -> `(when:`
                                lineas.push_back(std::string("@") + nombre +
                                                 "(" + w.substr(2) + ")");
                        };
                    flag("pure", [](const FnData &d) { return d.pure; });
                    flag("nothrow", [](const FnData &d) { return !d.throws; });
                    flag("nopanic", [](const FnData &d) { return !d.panics; });

                    // @alloc/@stack en dos dimensiones: agrupa por el par
                    // (parcial,total) y emite forma corta `@X(N)` cuando
                    // parcial==total (N=total, el peor caso), o nombrada
                    // `@X(partial: P, total: T)` cuando difieren.  Un total no
                    // acotable (pila con recursion) se emite solo con parcial.
                    auto num =
                        [&](const char *nombre,
                            const std::function<uint64_t(const FnData &)> &gp,
                            const std::function<uint64_t(const FnData &)> &gt) {
                            emitir(
                                [&](const FnData &d) {
                                    return std::to_string(gp(d)) + "|" +
                                           std::to_string(gt(d));
                                },
                                [&](const std::string &v,
                                    const std::string &w) {
                                    const size_t bar = v.find('|');
                                    const std::string ps = v.substr(0, bar);
                                    const std::string ts = v.substr(bar + 1);
                                    const uint64_t p = std::stoull(ps);
                                    const uint64_t t = std::stoull(ts);
                                    std::string dims;
                                    if (t == analyze::STACK_UNBOUNDED)
                                        dims = "partial: " +
                                               ps; // total no acotable
                                    else if (p == t)
                                        dims = ts; // forma corta = total
                                    else
                                        dims =
                                            "partial: " + ps + ", total: " + ts;
                                    return std::string("@") + nombre + "(" +
                                           dims + w + ")";
                                });
                        };
                    num(
                        "alloc",
                        [](const FnData &d) { return d.alloc_partial; },
                        [](const FnData &d) { return d.alloc_total; });
                    num(
                        "stack",
                        [](const FnData &d) { return d.stack_partial; },
                        [](const FnData &d) { return d.stack_total; });

                    emitir(
                        [](const FnData &d) {
                            return d.partial_pre + "|" + d.partial_post + "|" +
                                   d.total_pre + "|" + d.total_post;
                        },
                        [&](const std::string &v, const std::string &w) {
                            std::vector<std::string> dim;
                            size_t p = 0, q;
                            std::string t = v;
                            while ((q = t.find('|', p)) != std::string::npos) {
                                dim.push_back(t.substr(p, q - p));
                                p = q + 1;
                            }
                            dim.push_back(t.substr(p));
                            if (dim.size() != 4) return std::string();
                            return "@complexity(partial_pre: " + dim[0] +
                                   ", partial_post: " + dim[1] +
                                   ", total_pre: " + dim[2] +
                                   ", total_post: " + dim[3] + w + ")";
                        });

                    anot_por_clave[clave] = std::move(lineas);
                }

                // --analyze-write: reescribir el fichero analizado.  Si no,
                // imprimir las anotaciones para copiar/pegar o inspeccionar.
                if (result.count("analyze-write")) {
                    if (!annotate_write_source(vx_path, orden_grupos, display,
                                               anot_por_clave))
                        return EXIT_FAILURE;
                } else {
                    std::cout
                        << "\nAnotaciones sugeridas.  Los contratos medidos"
                           " que cada funcion deberia llevar; copialos "
                           "delante de la definicion.\n";
                    std::cout << "==========================================="
                                 "==================\n";
                    for (const auto &clave : orden_grupos) {
                        auto it = anot_por_clave.find(clave);
                        if (it == anot_por_clave.end()) continue;
                        std::cout << "  // " << display[clave] << "\n";
                        for (const auto &l : it->second)
                            std::cout << "  " << l << "\n";
                        std::cout << "\n";
                    }
                }
            }
        }

        std::cout << "=================================================="
                     "===========\n";
        std::cout << "Funciones analizadas: " << mc_post.functions.size()
                  << "; contratos con discrepancia: " << mismatches << "\n";
        return EXIT_SUCCESS;
    }

    // Volcado del indice semantico por-declaracion (hash de contenido + grafo
    // de deps).  Sustrato de la compilacion incremental granular / distribuida:
    // permite comprobar que editar un simbolo solo cambia SU hash.
    if (result.count("dump-semantic-index")) {
        const std::string vx_path =
            result["dump-semantic-index"].as<std::string>();
        std::string src;
        if (!vx::leer_fuente(vx_path, src)) {
            std::cerr << "error: no se pudo abrir '" << vx_path << "'\n";
            return EXIT_FAILURE;
        }
        vx::Diagnostics diags;
        vx::Lexer lx(src, vx_path, diags);
        vx::Parser p(lx, diags);
        auto mod = p.parse_program();
        if (!mod) {
            std::cerr << "error: fallo al parsear '" << vx_path << "'\n";
            return EXIT_FAILURE;
        }
        vx::SemanticIndex idx = vx::build_semantic_index(*mod, src, vx_path);
        std::cout << vx::semantic_index_to_json(idx) << "\n";
        return EXIT_SUCCESS;
    }

    // Ejemplo: vm.exe --vesta src/main.vx -o main.velb
    if (result.count("vesta") || result.count("vx")) {
        const std::string vx_path = result.count("vesta")
                                        ? result["vesta"].as<std::string>()
                                        : result["vx"].as<std::string>();
        bool emit_only = result.count("vx-emit-only") > 0;
        bool emit_ir = result.count("vx-emit-ir") > 0;

        // PGO consumer: si se paso --profile <path>, cargar '<path>.lines' (el
        // perfil de branches por linea producido por un run previo) para que la
        // if-conversion decida con datos medidos.  VESTA_BRANCH_PROFILE sigue
        // funcionando como alternativa.
        if (result.count("profile")) {
            const std::string lines =
                result["profile"].as<std::string>() + ".lines";
            const int nload = ir::load_branch_profile(lines.c_str());
            if (nload > 0)
                vesta::scout() << "[pgo] perfil de branches cargado: " << lines
                               << " (" << nload << " lineas)\n";
        }

        // Flags de diagramas (Mermaid y/o Graphviz).  --diagram-all activa
        // los 4 diagramas; --diagram-format elige el formato de salida.
        const bool diag_all = result.count("diagram-all") > 0;
        const bool diag_vx = diag_all || result.count("diagram-vx") > 0;
        const bool diag_ir_pre = diag_all || result.count("diagram-ir") > 0;
        const bool diag_ir_post =
            diag_all || result.count("diagram-ir-opt") > 0;
        const bool diag_vel = diag_all || result.count("diagram-vel") > 0;

        // Parsear --diagram-format: mermaid | graphviz | both.
        // Lower-case para tolerar "Mermaid", "GraphViz", "BOTH", etc.
        std::string diag_fmt = result.count("diagram-format") > 0
                                   ? result["diagram-format"].as<std::string>()
                                   : std::string("mermaid");
        for (auto &c : diag_fmt)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        // Formatos: mermaid | graphviz/dot | html | both (=mermaid+graphviz) |
        // all (=los tres).  "html" produce paginas interactivas autocontenidas.
        bool emit_mermaid =
            (diag_fmt == "mermaid" || diag_fmt == "both" || diag_fmt == "all");
        bool emit_graphviz = (diag_fmt == "graphviz" || diag_fmt == "dot" ||
                              diag_fmt == "both" || diag_fmt == "all");
        bool emit_html = (diag_fmt == "html" || diag_fmt == "all");
        if (!emit_mermaid && !emit_graphviz && !emit_html) {
            std::cerr << "[diagram] Formato desconocido: '" << diag_fmt
                      << "' (usar mermaid | graphviz | html | both | all). "
                         "Defaulting a mermaid.\n";
            emit_mermaid = true;
        }

        // parsear --vx-base (VA base en hex).  0x0 = comportamiento
        // por defecto (caller).  Para plugins cargados via loadmodule usar
        // un valor distinto (ej. 0x10000000) para evitar solapamiento con
        // el caller cuyo code section vive en 0x0..N.
        uint64_t vx_base_addr = 0;
        if (result.count("vx-base")) {
            const std::string &s = result["vx-base"].as<std::string>();
            try {
                vx_base_addr =
                    std::stoull(s, nullptr, 0); // base 0 = autodetect 0x prefix
            } catch (...) {
                std::cerr << "[vx] --vx-base invalido: " << s << "\n";
                return EXIT_FAILURE;
            }
        }

        /* Los ficheros que el preprocesador acabe leyendo.  Se declara aqui,
         * fuera del bloque de VPP, porque quien los necesita es el guardado del
         * cache mucho mas abajo: son dependencias como cualquier otra. */
        std::vector<std::string> vpp_included_files;

        // 1 Leer el .vx (con un solo fin de linea, ver vx::leer_fuente).
        std::string vx_source;
        if (!vx::leer_fuente(vx_path, vx_source)) {
            std::cerr << "[vx] No se puede abrir: " << vx_path << "\n";
            return EXIT_FAILURE;
        }

        // 2 Aplicar VPP (mismo pipeline que run_worker).  Esto es
        // best-effort: si una macro genera sintaxis no soportada por Vesta,
        // el frontend reportara el error con la posicion preprocesada.
#ifdef VESTA_HAS_PREPROCESSOR
        {
            vpp::Preprocessor pp;
            std::string source_dir =
                std::filesystem::path(vx_path).parent_path().string();
            pp.options().include_paths.push_back(source_dir);
            std::string exe_dir =
                std::filesystem::path(fs::get_executable_path())
                    .parent_path()
                    .string();
            pp.options().import_paths.push_back(exe_dir +
                                                "/preprocessor/include_lib");
            pp.options().import_paths.push_back(exe_dir + "/include_lib");
            {
                std::string _plib =
                    std::filesystem::path(exe_dir).parent_path().string();
                if (!_plib.empty()) {
                    pp.options().import_paths.push_back(_plib + "/include_lib");
                    pp.options().import_paths.push_back(
                        _plib + "/preprocessor/include_lib");
                }
            }
            pp.options().import_paths.push_back(source_dir);
#ifdef _WIN32
            pp.options().predefines.push_back("__VPP_WINDOWS__");
#elif defined(__linux__)
            pp.options().predefines.push_back("__VPP_LINUX__");
#elif defined(__APPLE__)
            pp.options().predefines.push_back("__VPP_MACOS__");
#endif
            std::string processed = pp.process(vx_source, vx_path);
            /* Lo que el preprocesador LEYO tambien es dependencia.  Un
             * `#include` cuenta igual que un `import`: si cambia, lo compilado
             * deja de valer.  Sin apuntarlo, el cache serviria el artefacto
             * viejo -- que no da error, da un resultado que ya no corresponde
             * al codigo, y eso se descubre tarde y mal. */
            vpp_included_files = pp.included_files();
            if (pp.diagnostics().has_errors()) {
                for (const auto &d : pp.diagnostics().diagnostics()) {
                    std::cerr << d.loc.file() << ":" << d.loc.line << ": "
                              << (d.level == vpp::DiagLevel::ERR ? "error: "
                                                                 : "warning: ")
                              << d.message << "\n";
                }
                return EXIT_FAILURE;
            }
            vx_source = std::move(processed);
        }
#endif

        // 3 Frontend Vesta: source -> IR -> .vel.
        // Sanitizar el nombre del modulo: el parser .vel rechaza
        // identificadores que empiezan con digito o que contienen caracteres no
        // [A-Za-z0-9_], pero los nombres de fichero pueden tener cualquier
        // cosa.  Aplicamos dos transformaciones: (a) si empieza por digito,
        // anteponer "m_"; (b) sustituir cualquier byte no alfanumerico por '_'.
        std::string raw_name = std::filesystem::path(vx_path).stem().string();
        std::string mod_name;
        mod_name.reserve(raw_name.size() + 2);
        if (!raw_name.empty() && (raw_name[0] >= '0' && raw_name[0] <= '9')) {
            mod_name = "m_";
        }
        for (char c : raw_name) {
            const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') || c == '_';
            mod_name.push_back(ok ? c : '_');
        }
        if (mod_name.empty()) mod_name = "main";

        vx::CompileOptions copts;
        copts.module_name = mod_name;
        // Nivel de opt UNIVERSAL via --ir-opt (mismo flag que VM/JIT/emit-ir).
        // Si el usuario NO lo pasa, AOT mantiene su default O2 (muy testeado);
        // con --ir-opt 0 se compila sin inlining (util para depurar con gdb:
        // las funciones no se funden y los breakpoints enganchan).
        copts.opt_level =
            (result.count("ir-opt") > 0) ? result["ir-opt"].as<int>() : 2;
        copts.dump_ir = emit_ir;     // habilita CompileResult::ir_text
        copts.native_poo = aot_mode; //  AOT.2.b: clases nativas en -m aot
        copts.exceptions_enabled = !aot_no_exceptions; // C3: configurable
        // -ffp-contract=off: IEEE estricto (sin contraccion FMA) a nivel de
        // modulo.  Se propaga a IrFunction::fp_contract en el lowering (fiable
        // cross-TU, a diferencia del global mutable).
        copts.fp_contract =
            !(result.count("ffp-contract") &&
              result["ffp-contract"].as<std::string>() == "off");
        // Bits del target para el inline-asm @Naked (validacion compile-time):
        // --aot-arch x86-32 -> 32 (si no, `jmp ecx` y demas fallan en mode64).
        if (aot_mode) {
            const std::string aa = result.count("aot-arch")
                                       ? result["aot-arch"].as<std::string>()
                                       : std::string("x86-64");
            copts.asm_target_bits =
                (aa == "x86-32" || aa == "x86_32" || aa == "i386") ? 32 : 64;
            // Ancho SIMD del TARGET para el matcher del vectorizador (mismo
            // mapeo que el codegen vreg deriva de FloatIsa): el binario AOT usa
            // el ancho de --float-isa, no el del host de build.  AUTO -> host
            // del build como estimacion (el multiversion-cpuid es futuro).
            const std::string fi = result.count("float-isa")
                                       ? result["float-isa"].as<std::string>()
                                       : std::string("sse2");
            if (fi == "avx")
                copts.aot_vec_width = 32;
            else if (fi == "avx512")
                copts.aot_vec_width = 64;
            else if (fi == "auto") {
                // AUTO: multiversion por cpuid en runtime.  El matcher hornea
                // el chunk con estrategia dual (element-wise 64, reduccion 16)
                // para que UN IR compile a las 3 variantes; el driver las
                // compila 3x.
                copts.aot_auto_vec = true;
                copts.aot_vec_width =
                    64; // element-wise max (la reduccion usa 16)
            } else
                copts.aot_vec_width = 16; // sse2 / x87
        }
        // Instrumentacion: aplica al IR independientemente del target
        // (bytecode VM, JIT, port C, etc.).  Validar valor aqui mismo.
        copts.instrument_mode = result["instrument"].as<std::string>();
        if (copts.instrument_mode != "none" &&
            copts.instrument_mode != "trace" &&
            copts.instrument_mode != "profile") {
            std::cerr << "[vx] --instrument invalido: " << copts.instrument_mode
                      << " (valores: none|trace|profile)\n";
            return 2;
        }
        // --vx-debug: emite `// @line N` en el .vel y genera la
        // seccion debug en el .velb final.  Por defecto OFF: el ejecutable
        // queda mas pequeno y la compilacion mas rapida.
        //
        // El mapa PC -> linea (seccion DVBG) se emite POR DEFECTO: es barato en
        // tamano, no cambia el codigo ejecutable, y habilita (a) el auto-PGO
        // del JIT (mapear los contadores de branches medidos a su linea fuente
        // para re-decidir la if-conversion) y (b) mejores stack traces.
        // --no-debug- info lo desactiva (para .velb minimos).
        // --vx-debug/--profile lo fuerzan aunque se pase --no-debug-info por
        // error.
        copts.emit_debug = (result.count("no-debug-info") == 0) ||
                           (result.count("vx-debug") > 0) ||
                           (result.count("profile") > 0);
        // Base de conocimiento de depuracion: solo si se pide una carpeta.  No
        // se activa con --vx-debug porque son cosas distintas -- aquella emite
        // el mapa de lineas DENTRO del ejecutable, esta escribe un grafo
        // aparte -- y encadenarlas obligaria a pagar una para tener la otra.
        copts.vxdbg_dir = result["vxdbg-dir"].as<std::string>();
        // Flags de diagramas: cada uno habilita la generacion del diagrama
        // correspondiente en CompileResult, segun el formato elegido por
        // --diagram-format.  Se escriben a archivos al final del bloque.
        copts.dump_mermaid_ast = emit_mermaid && diag_vx;
        copts.dump_mermaid_ir_pre = emit_mermaid && diag_ir_pre;
        copts.dump_mermaid_ir_post = emit_mermaid && diag_ir_post;
        copts.dump_mermaid_vel = emit_mermaid && diag_vel;
        copts.dump_graphviz_ast = emit_graphviz && diag_vx;
        copts.dump_graphviz_ir_pre = emit_graphviz && diag_ir_pre;
        copts.dump_graphviz_ir_post = emit_graphviz && diag_ir_post;
        copts.dump_graphviz_vel = emit_graphviz && diag_vel;
        copts.dump_html_ast = emit_html && diag_vx;
        copts.dump_html_ir_pre = emit_html && diag_ir_pre;
        copts.dump_html_ir_post = emit_html && diag_ir_post;
        copts.dump_html_vel = emit_html && diag_vel;

        // Flag --port=<lang>: si presente, configurar el transpiler IR ->
        // codigo. El frontend Vesta llama al port::Transpiler tras la fase de
        // optimizacion del IR; el resultado queda en cr.port_text para que aqui
        // lo escribamos a archivo con la extension correspondiente.
        if (result.count("emit-header")) {
            copts.emit_header = true;
        }
        if (result.count("port")) {
            copts.port_target = result["port"].as<std::string>();
            // Validacion temprana del target: solo 'c' en v1.
            if (copts.port_target != "c") {
                std::cerr << "[port] Target desconocido: '" << copts.port_target
                          << "'.  Soportados: c.\n";
                return EXIT_FAILURE;
            }
            // Parsear los flags --port-gc / --port-exc / --port-types.
            const std::string &gc_s = result["port-gc"].as<std::string>();
            if (!port::parse_gc_mode(gc_s, copts.port_options.gc)) {
                std::cerr << "[port] --port-gc invalido: " << gc_s
                          << " (valores: none|vesta|boehm)\n";
                return EXIT_FAILURE;
            }
            const std::string &exc_s = result["port-exc"].as<std::string>();
            if (!port::parse_exc_mode(exc_s, copts.port_options.exc)) {
                std::cerr << "[port] --port-exc invalido: " << exc_s
                          << " (valores: none|setjmp|returncode)\n";
                return EXIT_FAILURE;
            }
            const std::string &str_s = result["port-strings"].as<std::string>();
            if (!port::parse_string_mode(str_s, copts.port_options.strings)) {
                std::cerr << "[port] --port-strings invalido: " << str_s
                          << " (valores: raw|managed)\n";
                return 2;
            }
            const std::string &ty_s = result["port-types"].as<std::string>();
            if (!port::parse_type_style(ty_s, copts.port_options.types)) {
                std::cerr << "[port] --port-types invalido: " << ty_s
                          << " (valores: stdint|builtin)\n";
                return EXIT_FAILURE;
            }
            copts.port_options.freestanding =
                result.count("port-freestanding") > 0;
            copts.port_options.stdlib_port_c_dir =
                result["port-stdlib-dir"].as<std::string>();
            copts.port_options.arch_target =
                result["port-arch"].as<std::string>();
            copts.port_options.aggressive_opt =
                (result.count("port-no-aggressive") == 0);
            copts.port_options.module_name = mod_name;
            copts.port_options.source_path = vx_path;
        }

        /* ===  MC.12: cache persistente para @Macros ===
         *
         * Cache dir: `./.cache/vx/` (cwd-relative).  Key = FNV-1a 64
         * sobre (cache_format_version + vx_path + vx_source).  File =
         * `.cache/vx/<hex_key>.velb`.
         *
         * Flow:
         *   1. Compute key.
         *   2. Si el cache hit existe, setear @c VESTA_MC_PREBUILT antes
         *      de la primera invocacion de @c compile_vx_source.  Una
         *      sola compilacion + VM eval directo.
         *   3. Si miss + el modulo tiene @Macros, ejecutar pase 1 (AST
         *      eval), persistir el .velb resultante al cache_path, luego
         *      pase 2 con @c VESTA_MC_PREBUILT seteado.  Dos compiles
         *      en frio.  Las siguientes corridas son cache-hit -> 1 compile.
         *
         * Cache invalidation: implicita.  Cualquier cambio en el byte
         * stream del fuente (incluso un comentario o whitespace) genera
         * un key distinto y por tanto miss.  Sin sweeper automatico --
         * el usuario puede borrar `.cache/vx/` para limpiar manualmente.
         */
        const uint8_t cache_format_version =
            2; /* Bump por MC.14 macro-scoped key */

        /* QUE CONTIENE el artefacto, no solo como se lee.
         *
         * La clave hasta ahora decia de QUE FUENTE se derivo y con QUE FORMATO
         * se lee, pero no que se metio dentro.  Y eso es una variable: lo que
         * la ComptimeVM necesita se puede producir compilando el PROGRAMA
         * ENTERO (lo de hoy) o solo el CONJUNTO COMPTIME (lo que se esta
         * construyendo, ~350x mas pequeno).  Con la misma clave para las dos
         * cosas, cambiar de productor deja en el cache un artefacto cuyo
         * contenido no es el que la clave promete -- y el cache no puede
         * detectarlo: lo carga y MIENTE.
         *
         * Ya paso, y costo caro: un artefacto INCOMPLETO persistido durante una
         * prueba enveneno todas las compilaciones siguientes (e2e 919/4 ->
         * 903/12), y el sintoma -- macros que dejan de resolver -- no apunta al
         * cache por ningun lado.  Se reviritio codigo CORRECTO tres veces
         * persiguiendolo, hasta que purgar `.cache/vx/` lo devolvio todo a su
         * sitio.
         *
         * Con la clase en la clave, un artefacto de otra clase sencillamente NO
         * SE ENCUENTRA: falla el hit, se reconstruye, y no hay nada que
         * detectar porque no llega a cargarse. */
        enum class ClaseArtefactoComptime : uint8_t {
            ProgramaEntero = 1, ///< el `.vel` del programa, ensamblado entero.
            ConjuntoComptime = 2, ///< solo lo que se ejecuta al compilar.
        };
        const uint8_t clase_artefacto =
            static_cast<uint8_t>(ClaseArtefactoComptime::ConjuntoComptime);

        /*  MC.14: macro-scoped cache key.  Hashea SOLO los rangos
         * source que contienen declaraciones `@Macro` (incluyendo
         * anotaciones precedentes como @Pure/@Inline).  Cambios en
         * codigo NO-macro (main, helpers no marcados, comentarios
         * fuera de macros) NO invalidan el cache.
         *
         * Implementacion text-scan: detecta `@Macro`, scanea atras al
         * inicio de linea + lineas de anotacion previas, scanea adelante
         * a la llave de cierre balanceada (saltando strings y comentarios
         * line-style).  Heuristica suficiente para 99% de codigo Vesta
         * estandar.  Edge cases (comentarios de bloque con `@Macro`
         * dentro, etc.) producen cache miss falso pero no incorrectness.
         *
         * Si NO hay @Macros en el fuente, fallback a hash full-source
         * (el cache no se usa en ese caso de todos modos). */
        /* #4: escanea los rangos de TODO el codigo comptime relevante para el
         * cache -- no solo @Macro, tambien `comptime` (fn/const/block) y los
         * helpers asm (@Naked/@Asm) que una comptime fn puede invocar.  Sin
         * esto, cambiar el body de una comptime fn (p.ej. su inline asm) no
         * invalidaba el cache scoped -> valor STALE.  Para cada trigger captura
         * desde el inicio de linea (+ anotaciones precedentes) hasta el fin de
         * la declaracion: body balanceado `{}` o, para consts, hasta `;`. */
        const auto find_macro_ranges = [](const std::string &src)
            -> std::vector<std::pair<size_t, size_t>> {
            std::vector<std::pair<size_t, size_t>> ranges;
            /* Fin del body balanceado desde la `{` en @p bs (salta strings y
             * comentarios de linea).  Devuelve el indice tras la `}`. */
            auto scan_body = [&src](size_t bs) -> size_t {
                int depth = 1;
                size_t i = bs + 1;
                while (i < src.size() && depth > 0) {
                    char c = src[i];
                    if (c == '"') {
                        ++i;
                        while (i < src.size() && src[i] != '"') {
                            if (src[i] == '\\' && i + 1 < src.size()) ++i;
                            ++i;
                        }
                        ++i;
                        continue;
                    }
                    if (c == '/' && i + 1 < src.size() && src[i + 1] == '/') {
                        while (i < src.size() && src[i] != '\n')
                            ++i;
                        continue;
                    }
                    if (c == '{')
                        ++depth;
                    else if (c == '}')
                        --depth;
                    ++i;
                }
                return i;
            };
            /* Inicio de la declaracion desde @p pos: retrocede al inicio de
             * linea + anotaciones @X precedentes. */
            auto decl_start = [&src](size_t pos) -> size_t {
                size_t line_start = pos;
                while (line_start > 0 && src[line_start - 1] != '\n')
                    --line_start;
                while (line_start > 0) {
                    size_t prev_end = line_start - 1;
                    if (prev_end == 0 || src[prev_end] != '\n') break;
                    size_t prev_start = prev_end;
                    while (prev_start > 0 && src[prev_start - 1] != '\n')
                        --prev_start;
                    size_t k = prev_start;
                    while (k < prev_end && (src[k] == ' ' || src[k] == '\t'))
                        ++k;
                    if (k < prev_end && src[k] == '@')
                        line_start = prev_start;
                    else
                        break;
                }
                return line_start;
            };
            auto is_word = [](char c) {
                return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                       (c >= '0' && c <= '9') || c == '_';
            };
            /* Triggers: @-anotaciones (siempre body) + `comptime` (body o `;`).
             * `require_word_bound` = true para `comptime` (excluir
             * `comptime_concat` etc. y evitar match en medio de un identifier).
             */
            struct Trig {
                const char *kw;
                bool require_word_bound;
            };
            const Trig triggers[] = {{"@Macro", false},
                                     {"@Naked", false},
                                     {"@Asm", false},
                                     {"comptime", true}};
            for (const auto &t : triggers) {
                const std::string kw = t.kw;
                size_t pos = 0;
                while ((pos = src.find(kw, pos)) != std::string::npos) {
                    const size_t after = pos + kw.size();
                    /* Word-boundary para keywords alfanumericos. */
                    if (t.require_word_bound) {
                        const bool lead_ok =
                            (pos == 0) || !is_word(src[pos - 1]);
                        const bool trail_ok =
                            (after >= src.size()) || !is_word(src[after]);
                        if (!lead_ok || !trail_ok) {
                            pos = after;
                            continue;
                        }
                    }
                    const size_t ls = decl_start(pos);
                    /* Fin de la declaracion: primer `{` vs primer `;` tras la
                     * keyword.  `{` antes -> body; si no -> const/var hasta
                     * `;`. */
                    size_t bs = src.find('{', after);
                    size_t sc = src.find(';', after);
                    size_t end;
                    if (bs != std::string::npos &&
                        (sc == std::string::npos || bs < sc)) {
                        end = scan_body(bs);
                    } else if (sc != std::string::npos) {
                        end = sc + 1; /* incluir el `;` */
                    } else {
                        end = src.size();
                    }
                    ranges.emplace_back(ls, end);
                    pos = (end > after) ? end : after;
                }
            }
            return ranges;
        };

        /*  MC.16: per-macro manifest diagnostico.  Computa hash
         * por macro y guarda un manifest junto al .velb cacheado.  En
         * un cache miss, compara con el manifest anterior (si existe)
         * para reportar QUE macros cambiaron.
         *
         * Foundational para true per-macro relink: cuando el linker
         * soporte compilacion incremental, esta info dira que macros
         * recompilar.  Por ahora solo diagnostico via VESTA_MC_VERBOSE. */
        const auto find_macro_ranges_with_names = [&](const std::string &src)
            -> std::vector<std::tuple<std::string, size_t, size_t>> {
            std::vector<std::tuple<std::string, size_t, size_t>> ranges;
            size_t pos = 0;
            while ((pos = src.find("@Macro", pos)) != std::string::npos) {
                size_t line_start = pos;
                while (line_start > 0 && src[line_start - 1] != '\n')
                    --line_start;
                while (line_start > 0) {
                    size_t prev_end = line_start - 1;
                    if (prev_end == 0 || src[prev_end] != '\n') break;
                    size_t prev_start = prev_end;
                    while (prev_start > 0 && src[prev_start - 1] != '\n')
                        --prev_start;
                    size_t k = prev_start;
                    while (k < prev_end && (src[k] == ' ' || src[k] == '\t'))
                        ++k;
                    if (k < prev_end && src[k] == '@') {
                        line_start = prev_start;
                    } else {
                        break;
                    }
                }
                size_t bs = src.find('{', pos + 6);
                if (bs == std::string::npos) break;
                /* Extraer nombre: tras @Macro hay typically:
                 *   @Macro\ncomptime string NAME(args) { ... }
                 * El nombre es el identifier ANTES del '('. */
                std::string macro_name;
                {
                    size_t paren = src.find('(', pos + 6);
                    if (paren != std::string::npos && paren < bs) {
                        size_t name_end = paren;
                        while (name_end > pos + 6 &&
                               (src[name_end - 1] == ' ' ||
                                src[name_end - 1] == '\t' ||
                                src[name_end - 1] == '\n')) {
                            --name_end;
                        }
                        size_t name_start = name_end;
                        while (name_start > pos + 6 &&
                               (std::isalnum(static_cast<unsigned char>(
                                    src[name_start - 1])) ||
                                src[name_start - 1] == '_')) {
                            --name_start;
                        }
                        if (name_end > name_start) {
                            macro_name =
                                src.substr(name_start, name_end - name_start);
                        }
                    }
                }
                if (macro_name.empty()) macro_name = "<anon>";

                int depth = 1;
                size_t i = bs + 1;
                while (i < src.size() && depth > 0) {
                    char c = src[i];
                    if (c == '"') {
                        ++i;
                        while (i < src.size() && src[i] != '"') {
                            if (src[i] == '\\' && i + 1 < src.size()) ++i;
                            ++i;
                        }
                        ++i;
                        continue;
                    }
                    if (c == '/' && i + 1 < src.size() && src[i + 1] == '/') {
                        while (i < src.size() && src[i] != '\n')
                            ++i;
                        continue;
                    }
                    if (c == '{')
                        ++depth;
                    else if (c == '}')
                        --depth;
                    ++i;
                }
                ranges.emplace_back(std::move(macro_name), line_start, i);
                pos = i;
            }
            return ranges;
        };

        const uint64_t cache_key = [&]() -> uint64_t {
            constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
            constexpr uint64_t FNV_PRIME = 1099511628211ULL;
            uint64_t h = FNV_OFFSET;
            /* La VERSION del formato del intermedio entra en la clave.
             *
             * Sin esto, un  precompilado de antes de un cambio de
             * formato se seguia usando y se leia con el layout viejo: los
             * campos salen corridos y el codigo comptime devuelve basura sin
             * que nada avise.  Se vio como cuatro casos devolviendo 0 donde
             * esperaban 42, y desde fuera parecia un fallo del compilador.
             *
             * Un artefacto cacheado tiene que dejar de valer cuando cambia
             * como se lee, no solo cuando cambia lo que se compilo. */
            for (unsigned i = 0; i < 2; ++i) {
                h ^= static_cast<uint8_t>((ir::IR_SECTION_VERSION >> (i * 8)) &
                                          0xFF);
                h *= FNV_PRIME;
            }
            h ^= cache_format_version;
            h *= FNV_PRIME;
            /* La CLASE del artefacto: sin esto, dos cosas distintas comparten
             * clave y el cache sirve una por la otra sin poder notarlo. */
            h ^= clase_artefacto;
            h *= FNV_PRIME;
            for (char c : vx_path) {
                h ^= static_cast<uint8_t>(c);
                h *= FNV_PRIME;
            }
            h ^= 0xFFu;
            h *= FNV_PRIME;
            const auto ranges = find_macro_ranges(vx_source);
            if (ranges.empty()) {
                /* Sin macros: hash full-source.  El cache no se usa
                 * (has_lowerable_macros=false impedira el populate),
                 * pero un key estable previene colisiones si el usuario
                 * compila el mismo path con/sin macros sobre el mismo
                 * archivo. */
                for (char c : vx_source) {
                    h ^= static_cast<uint8_t>(c);
                    h *= FNV_PRIME;
                }
            } else {
                /* Hash solo los rangos macro + separadores. */
                for (const auto &r : ranges) {
                    const size_t end = (r.second < vx_source.size())
                                           ? r.second
                                           : vx_source.size();
                    for (size_t i = r.first; i < end; ++i) {
                        h ^= static_cast<uint8_t>(vx_source[i]);
                        h *= FNV_PRIME;
                    }
                    h ^= 0xFEu; /* separador entre macros distintos. */
                    h *= FNV_PRIME;
                }
            }
            return h;
        }();
        char cache_key_hex[17];
        std::snprintf(cache_key_hex, sizeof(cache_key_hex), "%016llx",
                      static_cast<unsigned long long>(cache_key));
        const std::string cache_dir = ".cache/vx";
        const std::string cache_prefix = cache_dir + "/" + cache_key_hex;
        const std::string cache_path = cache_prefix + ".velb";
        const bool cache_hit = std::filesystem::exists(cache_path);
        const bool user_already_set_prebuilt =
            !util::flag_text(util::FlagId::McPrebuilt).empty();
        const bool verbose_mc = util::flag_on(util::FlagId::McVerbose);

        /* CACHE HIT path: setear env var ANTES del primer compile_vx_source.
         * Solo 1 invocacion de compile, con VM eval activo desde el inicio. */
        if (cache_hit && !user_already_set_prebuilt) {
#if defined(_WIN32)
            _putenv_s("VESTA_MC_PREBUILT", cache_path.c_str());
#else
            setenv("VESTA_MC_PREBUILT", cache_path.c_str(), 1);
#endif
            if (verbose_mc) {
                std::cerr << "[mc-cache] hit: " << cache_path << "\n";
            }
        }

        //  M5.B: PROJECT CACHE LOOKUP.  Si el source tiene imports,
        // intentar cache hit a nivel @c .velb final.  Si todos los hashes
        // de root + deps recursivos coinciden con los cacheados, copiar
        // el @c .velb cacheado al output y SALTAR todo el compile +
        // link.  Desactivable via @c VX_NO_PROJECT_CACHE=1.
        const bool project_cache_enabled =
            !util::flag_on(util::FlagId::NoProjectCache);
        const bool project_cache_verbose =
            util::flag_on(util::FlagId::VerboseProjectCache);
        const bool has_imports = vx::vx_source_has_imports(vx_source);

        vx::ProjectCacheKey pck;
        pck.opt_level = copts.opt_level;
        pck.emit_debug = copts.emit_debug;
        pck.vx_base = 0; // no usado por compile_vx_project; queda 0
        pck.instrument_mode = copts.instrument_mode;
        pck.port_target = copts.port_target;
        pck.comptime_prebuilt =
            !util::flag_text(util::FlagId::McPrebuilt).empty();
        /* De donde salen los modulos que no son del proyecto.  Es lo mismo que
         * lo de abajo: si algo que cambia lo compilado no esta en la clave, un
         * acierto sirve un fichero que no corresponde. */
        pck.stdlib_dir = vx::detect_stdlib_vx_dir();
        pck.vx_path = util::flag_text(util::FlagId::VxPath);
        /* Que artefacto se pidio.  El cache guarda el fichero FINAL, asi que
         * pedir un binario nativo y pedir un `.velb` no pueden compartir
         * entrada -- ni dos binarios de arquitecturas distintas.  Todo lo que
         * cambia lo que sale tiene que estar aqui: si algo se queda fuera, un
         * acierto sirve un fichero que no es el que se pidio. */
        pck.aot = aot_mode;
        if (aot_mode) {
            pck.aot_arch = result["aot-arch"].as<std::string>();
            if (result.count("format"))
                pck.aot_format = result["format"].as<std::string>();
            if (result.count("emit"))
                pck.aot_emit = result["emit"].as<std::string>();
            {
                std::string os_t, arch_t;
                vx::get_aot_condcomp_target(os_t, arch_t);
                pck.aot_target = os_t + "/" + arch_t;
            }
            pck.aot_tier = std::to_string(static_cast<int>(aot_tier));
            std::ostringstream perfil;
            perfil << (aot_freestanding ? "F" : "")
                   << (aot_no_exceptions ? "E" : "") << (aot_no_io ? "I" : "")
                   << (aot_no_mem ? "M" : "")
                   << (result.count("no-pie") ? "P" : "") << ":"
                   << result["float-isa"].as<std::string>() << ":"
                   << (result.count("debug-info")
                           ? result["debug-info"].as<std::string>()
                           : "")
                   << ":"
                   << (result.count("bin-base")
                           ? result["bin-base"].as<std::string>()
                           : "")
                   << ":"
                   << (result.count("sysroot")
                           ? result["sysroot"].as<std::string>()
                           : "");
            pck.aot_perfil = perfil.str();
        }
        const uint32_t opts_hash = vx::project_cache_opts_hash(pck);
        /* Los avisos son del frontend y no dependen de que artefacto se pida,
         * asi que llevan su propia huella: una sola copia sirve a los tres
         * backends, y cambiar de backend no los pierde. */
        const uint32_t diag_hash = vx::project_cache_diag_hash(pck);
        /* Donde se esta compilando.  CONSERVADOR: mientras los productores no
         * sepan decir que un aviso suyo es universal, se marca con el objetivo
         * actual -- en el peor caso se comporta como antes (se recalcula) y
         * nunca se afirma en un sitio algo comprobado en otro. */
        analysis::asa::Scope donde;
        donde.isa = pck.aot_arch.empty() ? "x86-64" : pck.aot_arch.c_str();
        donde.os = pck.aot_target.c_str();
        donde.backend = pck.aot ? "aot" : "vm";
        /* Restringir obliga a decir por que: lo que el compilador avisa de un
         * programa depende del objetivo, porque `@Target` descarta
         * declaraciones segun el. */
        donde.why = "diag.depende_del_objetivo";

        // Path canonico del root para el cache key.
        std::string canonical_root;
        try {
            canonical_root =
                std::filesystem::weakly_canonical(vx_path).string();
        } catch (...) {
            canonical_root = vx_path;
        }
        const std::string pc_dir = vx::default_project_cache_dir();
        const std::string pc_path =
            vx::project_cache_path(canonical_root, pc_dir);

        // Artefactos que SOLO se producen recorriendo el pipeline completo
        // (no estan en el .velb cacheado): diagramas (mmd/dot/html), dump de
        // IR (--vx-emit-ir) y transpile (--port).  Si el usuario los pide,
        // saltamos el hit del project-cache para forzar la compilacion y que
        // se generen; de lo contrario el cache hit los omitiria en silencio.
        // `--vx-emit-only` pide precisamente el `.vel`, que tampoco esta en el
        // `.velb` cacheado.  Faltaba en esta lista, asi que con un programa
        // que importa modulos el acierto de cache devolvia el binario y el
        // `.vel` no aparecia: el mismo comando hacia dos cosas distintas segun
        // el programa tuviera imports o no.  Peor que la molestia es lo que
        // implicaba: los volcados de diagnostico dejaban de venir del mismo
        // recorrido que produce el binario, y compararlos llevaba a
        // conclusiones que no significaban nada.
        const bool wants_pipeline_artifacts =
            diag_vx || diag_ir_pre || diag_ir_post || diag_vel || emit_ir ||
            emit_only || !copts.port_target.empty();

        /* El cache guarda el fichero FINAL, sea cual sea: un `.velb` de la
         * maquina virtual o un binario nativo.
         *
         * El AOT se lo saltaba entero, y con razon en su momento: la clave no
         * distinguia que artefacto se habia pedido, asi que un acierto le
         * habria servido un `.velb` a quien pedia un `.exe`.  Pero la respuesta
         * era arreglar la clave, no apagar el cache -- volver a construir sin
         * haber cambiado nada costaba lo mismo que construir por primera vez
         * (127 ms contra los 14 del camino de la VM).  Ahora la clave lleva
         * arch, formato, tipo de emision, objetivo, nivel de runtime y el resto
         * de opciones que cambian lo emitido. */
        if (project_cache_enabled && !wants_pipeline_artifacts) {
            uint32_t cached_opts_hash = 0;
            std::vector<vx::ProjectCacheDep> cached_deps;
            std::vector<uint8_t> cached_velb;
            if (vx::project_cache_load(pc_path, cached_opts_hash, cached_deps,
                                       cached_velb) &&
                cached_opts_hash == opts_hash && !cached_deps.empty() &&
                !cached_velb.empty() &&
                vx::project_cache_validate(cached_deps, copts.emit_debug)) {
                // HIT: escribir el artefacto cacheado al output y salir.  En
                // AOT el fichero final es `out_prefix` tal cual (ya trae su
                // extension); en la VM se le anade `.velb`.
                const std::string out_velb =
                    aot_mode ? out_prefix : (out_prefix + ".velb");
                /* Con las llamadas del SISTEMA, no con `std::ofstream`.
                 *
                 * Este es el camino que mas se recorre -- un acierto de cache
                 * es lo que se paga cien veces al dia -- y aqui se escribe el
                 * artefacto entero: 7,9 MiB en un proyecto de 6k lineas.  Con
                 * el flujo de la biblioteca estandar, VTune ponia 38,7 ms de
                 * los ~80 de CPU del acierto en el `write` de msvcrt: los bytes
                 * ya estan todos en memoria, asi que su capa de bufer no aporta
                 * nada y se paga entera.
                 *
                 * `write_file_atomic` escribe con las llamadas nativas y ademas
                 * publica con un renombrado, con lo que el artefacto de salida
                 * nunca se ve a medias -- que antes si podia pasar. */
                if (util::write_whole_file(out_velb, cached_velb)) {
                    {
                        /* Los avisos que dio la compilacion que lleno este
                         * cache se vuelven a emitir.  Sin esto, compilar dos
                         * veces lo mismo da salidas distintas -- y la segunda,
                         * la callada, es la que el usuario ve casi siempre en
                         * un proyecto grande, que es donde el cache acierta.
                         * Se rehacen desde sus DATOS, asi que salen en el
                         * idioma activo aunque se guardaran en otro. */
                        std::vector<vx::Diagnostic> guardados;
                        if (vx::project_cache_load_diags(pc_path, diag_hash,
                                                         guardados, donde)) {
                            for (const auto &d : guardados)
                                vx::print_diagnostic(std::cerr, d);
                        }
                        /* Y la raiz de diagnostico, por el mismo motivo que los
                         * avisos de arriba: sin esto el binario servido desde
                         * el cache no tiene nada que lo explique, y recompilar
                         * tampoco lo arregla porque vuelve a acertar aqui.  El
                         * identificador se saca del fichero que se acaba de
                         * escribir, que es de donde tiene que salir. */
                        std::string map_hex, spans_hex;
                        if (vx::project_cache_load_vxdbg(pc_path, map_hex,
                                                         spans_hex)) {
                            // Con los bytes que ya tenemos: el fichero se acaba
                            // de escribir con ellos, releerlo seria leer dos
                            // veces lo mismo en el camino que mas se recorre.
                            vx::publish_vxdbg_artifact(
                                out_velb, vxdbg::ContentHash::from_hex(map_hex),
                                vxdbg::ContentHash::from_hex(spans_hex),
                                copts.vxdbg_dir, &cached_velb);
                        }
                        if (project_cache_verbose) {
                            std::cerr << "[vx-project-cache] hit: " << pc_path
                                      << " -> " << out_velb << " ("
                                      << cached_velb.size() << " bytes)\n";
                        }
                        return EXIT_SUCCESS;
                    }
                }
                // Si fallo escribir, caemos al compile normal (no es fatal).
                if (project_cache_verbose) {
                    std::cerr << "[vx-project-cache] hit pero write fallo, "
                                 "recompile\n";
                }
            } else if (project_cache_verbose) {
                std::cerr << "[vx-project-cache] miss: " << pc_path << "\n";
            }
        }

        //  M.2.e: si el source tiene `import`, dispatch al
        // compilador multi-modulo.  Este construye el dep graph,
        // compila cada dep en topo order, inyecta .vxi, y mergea
        // todas las funciones en un solo .vel.
        vx::CompileResult cr =
            has_imports ? vx::compile_vx_project(vx_path, copts)
                        : vx::compile_vx_source(vx_source, vx_path, copts);

        /*  MC.16+: diagnostico de macros que el lowering rechazo
         * por usar builtins comptime-only no aliasables (comptime_compile,
         * static_assert, etc.) o comptime globals.  Estos macros caen al
         * AST evaluator y NO se benefician del cache/VM/memo.  Imprimir
         * via VESTA_MC_VERBOSE para que el usuario sepa por que. */
        if (verbose_mc && cr.ok && !cr.macro_skip_reasons.empty()) {
            for (const auto &sk : cr.macro_skip_reasons) {
                std::cerr << "[mc-lower] " << sk.first << ": AST-only ("
                          << sk.second << ")\n";
            }
        }

        /* Limpiar env var si lo seteamos arriba (cache hit). */
        if (cache_hit && !user_already_set_prebuilt) {
#if defined(_WIN32)
            _putenv_s("VESTA_MC_PREBUILT", "");
#else
            unsetenv("VESTA_MC_PREBUILT");
#endif
        }

        if (!cr.ok) {
            vx::render_diagnostics(
                std::cerr, cr.diagnostics,
                vx::parse_diag_format(result["diag-format"].as<std::string>()));
            return EXIT_FAILURE;
        }

        // ------------------------------------------------------------------
        // Comptime two- para AOT.  El emit nativo (bloque `if (aot_mode)`
        // de abajo) usa `cr` y RETORNA antes del two- del path .velb (que
        // vive tras el emit AOT), asi que el codigo comptime que se ejecuta en
        // el ComptimeVM (p.ej. inline asm en una comptime fn) no se resolveria
        // en AOT -> daria placeholder.  Aqui hacemos el mismo two- ANTES
        // del emit: compilar el pass-1 a un `.velb` cacheado (contiene el
        // bytecode comptime `__macro_*`), cargarlo via VESTA_MC_PREBUILT, y
        // recompilar (pass 2) para que los call sites comptime invoquen la VM.
        // Solo en cache-miss (en hit el prebuilt ya se seteo antes del pass 1).
        // ------------------------------------------------------------------
        if (aot_mode && !cache_hit && cr.has_lowerable_macros &&
            !user_already_set_prebuilt) {
            std::error_code aec;
            std::filesystem::create_directories(cache_dir, aec);
            /* CRITICO: el prebuilt lo carga y EJECUTA el ComptimeVM, que corre
             * BYTECODE VM -- no codigo nativo.  Con native_poo el `cr` de
             * arriba bajo las clases/@Naked a lowering NATIVO, que el
             * ComptimeVM no ejecuta (el CALLN a vrt:naked_dispatch, p.ej., no
             * se materializa igual) -> las comptime fn con asm daban 0.  Por
             * eso compilamos una version VM-lowered (native_poo=false) SOLO
             * para el prebuilt del ComptimeVM; el binario final AOT lo produce
             * el pass-2 con native_poo. */
            if (recompilar_con_maquina_de_compilacion(cr, vx_path, vx_source,
                                                      copts, cache_prefix)) {
                if (verbose_mc) {
                    std::cerr << "[mc-cache] aot two- populated: " << cache_path
                              << "\n";
                }
                /* Si pass-2 fallo (assert real / error), propagar y abortar. */
                if (!cr.ok) {
                    for (const auto &d : cr.diagnostics.all())
                        vx::print_diagnostic(std::cerr, d);
                    return EXIT_FAILURE;
                }
            }
        }

        // ------------------------------------------------------------------
        //  AOT (Paso 1): modo -m aot.  Analiza la compatibilidad nativa
        // del modulo (sin emitir binario aun -- eso es el Paso 2: codegen
        // HOST_LEAF -> ObjectWriter).  El IR optimizado viaja en
        // cr.ir_section_bytes (mismo @ir que consume el JIT); se deserializa
        // y se pasa al analizador AOT.1.
        // ------------------------------------------------------------------
        // --vx-emit-ir: escribir el dump del SSA IR ANTES del codegen.  El
        // bloque `if (aot_mode)` de abajo RETORNA tras el emit nativo, asi que
        // el punto de escritura de mas abajo nunca se alcanza en AOT.  Ubicarlo
        // aqui cubre TODOS los modos (aot/vm/velb) de forma uniforme y hace que
        // `--vx-emit-ir` respete el TARGET (los @Target de los deps se
        // resuelven segun --format/--aot-arch, no segun el host).
        if (emit_ir) {
            std::string ir_path = out_prefix.empty()
                                      ? (copts.module_name + ".ir")
                                      : (out_prefix + ".ir");
            std::ofstream ofs_ir(ir_path);
            if (!ofs_ir.is_open()) {
                std::cerr << "[vx] No se puede escribir: " << ir_path << "\n";
                return EXIT_FAILURE;
            }
            ofs_ir << cr.ir_text;
            vesta::scout() << "[vx] .ir generado: " << ir_path << "\n";
            return EXIT_SUCCESS;
        }

        if (aot_mode) {
            // Emision AOT nativa: delegada a vesta::tc::compile_aot
            // (src/toolchain/aot_build.cpp) para no monolitizar main.cpp.  Los
            // flags de la CLI se mapean a una struct de opciones desacoplada de
            // cxxopts (asi el LSP tambien puede emitir AOT embebido).
            vesta::tc::AotOptions aopt;
            aopt.tier = aot_tier;
            aopt.freestanding = aot_freestanding;
            aopt.no_exceptions = aot_no_exceptions;
            aopt.no_io = aot_no_io;
            aopt.no_mem = aot_no_mem;
            aopt.arch = result["aot-arch"].as<std::string>();
            aopt.float_isa = result["float-isa"].as<std::string>();
            {
                /* Un eje por MECANISMO, separados por punto.  Se parte la
                 * CADENA y no se lee como numero en coma flotante: 0.1 y 2.1
                 * no son exactos en binario -- 2.1 es 2.0999999... -- y
                 * extraer el digito de ahi da sustos.  Ademas asi se puede
                 * anadir un tercer eje manana (`1.2.3`), que como flotante ni
                 * siquiera seria expresable.
                 *
                 * Un entero suelto sigue siendo lo de siempre: nivel DWARF, y
                 * el resto de ejes a cero. */
                const std::string niveles =
                    result["debug-info"].as<std::string>();
                size_t desde = 0;
                int eje = 0;
                while (desde <= niveles.size() && eje < 2) {
                    const size_t punto = niveles.find('.', desde);
                    const std::string parte = niveles.substr(
                        desde, punto == std::string::npos ? std::string::npos
                                                          : punto - desde);
                    const int v = parte.empty() ? 0 : std::atoi(parte.c_str());
                    if (eje == 0)
                        aopt.debug_level = v; // DWARF / symtab
                    else
                        aopt.lang_debug_level = v; // el nuestro
                    ++eje;
                    if (punto == std::string::npos) break;
                    desde = punto + 1;
                }
            }
            if (result.count("format"))
                aopt.format = result["format"].as<std::string>();
            if (result.count("emit"))
                aopt.emit = result["emit"].as<std::string>();
            aopt.no_pie = result.count("no-pie") > 0;
            if (result.count("bin-base"))
                aopt.bin_base = result["bin-base"].as<std::string>();
            if (result.count("sysroot"))
                aopt.sysroot = result["sysroot"].as<std::string>();
            aopt.argv0 = argv[0];
            aopt.source_path = vx_path;
            const int rc_aot =
                vesta::tc::compile_aot(cr, copts, out_prefix, aopt);
            /* Y se guarda, para que volver a construir sin haber cambiado nada
             * no cueste construirlo otra vez.  Solo si salio bien: cachear un
             * fallo seria servirlo despues como si fuera el artefacto. */
            if (rc_aot == EXIT_SUCCESS && project_cache_enabled &&
                !wants_pipeline_artifacts) {
                std::vector<uint8_t> abytes;
                if (util::read_whole_file(out_prefix, abytes) &&
                    !abytes.empty()) {
                    // Las mismas dependencias que en el camino de bytecode:
                    // el fuente raiz y lo que el preprocesador leyo.
                    std::vector<std::string> deps_extra_aot =
                        vpp_included_files;
                    deps_extra_aot.push_back(canonical_root);
                    guardar_cache_de_proyecto(pc_path, opts_hash, diag_hash,
                                              donde, cr, copts.emit_debug,
                                              abytes, project_cache_verbose,
                                              deps_extra_aot);
                }
            }
            return rc_aot;
        }

        /* CACHE MISS + @Macros presentes: hacer two- y persistir
         * el resultado a `.cache/vx/<key>.velb` para futuras corridas. */
        if (!cache_hit && cr.has_lowerable_macros &&
            !user_already_set_prebuilt) {
            std::error_code ec;
            std::filesystem::create_directories(cache_dir, ec);

            /*  MC.16: per-macro manifest diagnostico.  Computamos
             * hash por macro del fuente actual y comparamos con manifest
             * anterior (si existe).  Reportamos via VESTA_MC_VERBOSE que
             * macros cambiaron -- foundation para futuro per-macro relink. */
            if (verbose_mc) {
                const auto current_ranges =
                    find_macro_ranges_with_names(vx_source);
                std::vector<std::pair<std::string, std::string>> current_hashes;
                current_hashes.reserve(current_ranges.size());
                for (const auto &r : current_ranges) {
                    const std::string &mname = std::get<0>(r);
                    const size_t start = std::get<1>(r);
                    const size_t end = std::get<2>(r);
                    constexpr uint64_t FNV_O = 14695981039346656037ULL;
                    constexpr uint64_t FNV_P = 1099511628211ULL;
                    uint64_t h = FNV_O;
                    for (size_t i = start; i < end && i < vx_source.size();
                         ++i) {
                        h ^= static_cast<uint8_t>(vx_source[i]);
                        h *= FNV_P;
                    }
                    char buf[17];
                    std::snprintf(buf, sizeof(buf), "%016llx",
                                  static_cast<unsigned long long>(h));
                    current_hashes.emplace_back(mname, buf);
                }
                /* Cargar manifest anterior si existe (key viejo = el del
                 * cache que acabamos de invalidar; lo buscamos por scan). */
                std::map<std::string, std::string> previous;
                bool had_previous = false;
                {
                    std::error_code sec;
                    for (const auto &entry :
                         std::filesystem::directory_iterator(cache_dir, sec)) {
                        if (!entry.is_regular_file()) continue;
                        const std::string p = entry.path().string();
                        if (p.size() > 9 &&
                            p.substr(p.size() - 9) == ".manifest") {
                            std::ifstream ifs(p);
                            std::string line;
                            while (std::getline(ifs, line)) {
                                const auto tab = line.find('\t');
                                if (tab != std::string::npos) {
                                    previous[line.substr(0, tab)] =
                                        line.substr(tab + 1);
                                }
                            }
                            had_previous = !previous.empty();
                            break; /* solo el primero, suficiente para diag */
                        }
                    }
                }
                if (had_previous) {
                    size_t changed = 0, added = 0;
                    std::set<std::string> seen;
                    for (const auto &cur : current_hashes) {
                        seen.insert(cur.first);
                        auto it = previous.find(cur.first);
                        if (it == previous.end()) {
                            std::cerr << "[mc-manifest] añadido: " << cur.first
                                      << "\n";
                            ++added;
                        } else if (it->second != cur.second) {
                            std::cerr << "[mc-manifest] cambio: " << cur.first
                                      << "\n";
                            ++changed;
                        }
                    }
                    for (const auto &prev : previous) {
                        if (!seen.count(prev.first)) {
                            std::cerr
                                << "[mc-manifest] eliminado: " << prev.first
                                << "\n";
                        }
                    }
                    std::cerr << "[mc-manifest] total=" << current_hashes.size()
                              << " cambios=" << changed << " añadidos=" << added
                              << "\n";
                }
                /* Escribir nuevo manifest. */
                const std::string manifest_path = cache_prefix + ".manifest";
                std::ofstream mfs(manifest_path);
                if (mfs) {
                    for (const auto &p : current_hashes) {
                        mfs << p.first << '\t' << p.second << '\n';
                    }
                }
            }

            /*  MC.14: cache sweeper TTL-based.  Antes de poblar el
             * nuevo cache file, escanea @c .cache/vx/ y borra archivos
             * cuyo mtime sea anterior a @c TTL dias (default 30, override
             * via env var @c VESTA_MC_CACHE_TTL_DAYS).  Solo corre en el
             * path de miss para evitar sobrecargar el path comun de hit.
             * Cost ~50us para directorios con <100 archivos -- despreciable
             * cuando ya estamos en miss path (que ya cuesta 7-10ms).
             *
             * Default agresivo (30 dias) para que el cache no crezca
             * indefinidamente; el usuario que use el cache regularmente
             * verá hits constantemente y los archivos no expiran.  Los
             * archivos de proyectos abandonados se limpian solos. */
            {
                uint64_t ttl_days = 30;
                {
                    /* Cap de 10 anyos: un valor absurdo no puede dejar
                     * ficheros para siempre ni borrarlos manana. */
                    const long v =
                        util::flag_int(util::FlagId::McCacheTtlDays, -1);
                    if (v >= 0 && v <= 3650)
                        ttl_days = static_cast<uint64_t>(v);
                }
                if (ttl_days > 0) {
                    const auto now_tp =
                        std::filesystem::file_time_type::clock::now();
                    const auto ttl = std::chrono::hours(24 * ttl_days);
                    size_t swept = 0;
                    std::error_code swec;
                    for (const auto &entry :
                         std::filesystem::directory_iterator(cache_dir, swec)) {
                        if (!entry.is_regular_file()) continue;
                        std::error_code mtec;
                        const auto mt = entry.last_write_time(mtec);
                        if (mtec) continue;
                        if (now_tp - mt > ttl) {
                            std::error_code rmec;
                            std::filesystem::remove(entry.path(), rmec);
                            if (!rmec) ++swept;
                        }
                    }
                    if (verbose_mc && swept > 0) {
                        std::cerr
                            << "[mc-cache] sweeper: " << swept
                            << " archivo(s) expirado(s) eliminado(s) (TTL "
                            << ttl_days << " dias)\n";
                    }
                }
            }

            /* Lo que la ComptimeVM necesita es el bytecode de lo que se EJECUTA
             * al compilar, no el del programa entero.  Aqui se ensamblaba
             * `cr.vel_text` -- el programa completo --, y eso es lo que hacia
             * que el artefacto fuese de 704 KB con 182 macros cuando las
             * funciones que de verdad se ejecutan al compilar son ocho.
             *
             * `cr.comptime_vel_text` es esa misma emision pero FILTRADA sobre
             * el IR ya bajado, con la clausura del grafo de llamadas incluida
             * para que sea auto-suficiente.  Si el modulo no tiene conjunto, se
             * ensambla el programa como antes. */
            const bool usar_conjunto = !cr.comptime_vel_text.empty();
            const std::string &vel_artefacto =
                usar_conjunto ? cr.comptime_vel_text : cr.vel_text;
            if (verbose_mc)
                std::cerr << "[mc-cache] artefacto desde "
                          << (usar_conjunto ? "el CONJUNTO comptime"
                                            : "el programa entero")
                          << ": " << vel_artefacto.size() << " bytes de .vel\n";
            /* Ensamblar DESDE MEMORIA: el texto lo acaba de producir el emisor,
             * asi que escribirlo a un `.vel.tmp` para que la linea siguiente lo
             * relea era un viaje por el disco de ida y vuelta.  Y ademas un
             * `.vel` que nadie pidio: el fichero es un artefacto que se
             * solicita
             * (`--vx-emit-only`), no un paso obligado del camino.
             *
             * El nombre se conserva porque los diagnosticos lo citan, no porque
             * se abra nada. */
            warn_unresolved_inject(cr, vx_path);
            std::string vel_en_memoria;
            if (copts.emit_debug) vel_en_memoria = "// @file " + vx_path + "\n";
            vel_en_memoria += vel_artefacto;
            /* El texto que se va a ensamblar, a un fichero, cuando se pide la
             * prueba del conjunto.  Cuando NO ensambla hay que poder LEERLO:
             * el ensamblador dice "Parse error" y una posicion suya, que no
             * lleva a ningun fuente porque este texto no es de nadie. */
            if (util::flag_on(util::FlagId::PruebaIrComptime)) {
                const std::string p = cache_prefix + ".conjunto.vel";
                std::ofstream f_ct(p, std::ios::binary);
                if (f_ct) f_ct << vel_en_memoria;
                std::cerr << "[comptime-ir] texto del conjunto: " << p << "\n";
            }
            const std::string tmp_vel_path = cache_prefix + ".vel.tmp";
            const int tmp_rc = asm_multi_process::run_worker_from_source(
                std::move(vel_en_memoria), tmp_vel_path, cache_prefix,
                /*skip_preprocessor=*/true,
                /*keep_labels=*/false,
                /*ir_section_bytes=*/&cr.ir_section_bytes,
                /*emit_map=*/false);
            if (tmp_rc == EXIT_SUCCESS) {
#if defined(_WIN32)
                _putenv_s("VESTA_MC_PREBUILT", cache_path.c_str());
#else
                setenv("VESTA_MC_PREBUILT", cache_path.c_str(), 1);
#endif
                //  M.2.e: same dispatch en el path two- del macro
                // cache.  Si el source tiene imports, usar compile_vx_project.
                vx::CompileResult cr2 =
                    vx::vx_source_has_imports(vx_source)
                        ? vx::compile_vx_project(vx_path, copts)
                        : vx::compile_vx_source(vx_source, vx_path, copts);
#if defined(_WIN32)
                _putenv_s("VESTA_MC_PREBUILT", "");
#else
                unsetenv("VESTA_MC_PREBUILT");
#endif
                /* pass-2 es AUTORITATIVO (compilado con el bytecode comptime
                 * cargado): adoptamos su cr SIEMPRE, incluso con errores (p.ej.
                 * un static_assert que resolvio a false con el valor real).
                 * Quedarnos con pass-1 (asserts diferidos SALTADOS) ocultaria
                 * el fallo -> compile con valores incorrectos. */
                cr = std::move(cr2);
                if (verbose_mc) {
                    std::cerr << "[mc-cache] miss + populated: " << cache_path
                              << "\n";
                }
                /* Cleanup del .vel temporal y del .velb-map (no de cache_path,
                 * que es el archivo cacheado y debe persistir). */
                std::remove(tmp_vel_path.c_str());
                const std::string cache_velb_map = cache_path + "-map";
                std::remove(cache_velb_map.c_str());
                /* Si pass-2 fallo (assert real / error), propagar y abortar. */
                if (!cr.ok) {
                    for (const auto &d : cr.diagnostics.all())
                        vx::print_diagnostic(std::cerr, d);
                    return EXIT_FAILURE;
                }
            } else {
                /* Y SI NO se pudo ensamblar, se DICE.
                 *
                 * Aqui habia un `if (ok) { ... }` sin `else`: la compilacion
                 * seguia como si nada, sin artefacto comptime y por tanto sin
                 * bytecode que ejecutar, y lo que dependia de el se quedaba con
                 * valores de relleno.  El ensamblador escupia su "Parse error"
                 * suelto, sin decir de que era ni que implicaba, y el programa
                 * salia distinto sin que nadie lo supiera.
                 *
                 * NO aborta: hoy hay modulos que caen aqui y siguen produciendo
                 * un binario que funciona.  Convertirlo en error duro es una
                 * decision aparte -- pero callarlo no era una opcion. */
                vx::Diagnostic d;
                d.level = vx::DiagLevel::WARN;
                d.code = "VXA051";
                d.args.push_back(copts.module_name.empty() ? vx_path
                                                           : copts.module_name);
                d.loc.file = vx_path;
                vx::print_diagnostic(std::cerr, d);
                std::remove(tmp_vel_path.c_str());
            }
        }

        // Mostrar warnings (cr.ok no impide los warnings).  En cr.ok no hay
        // errores, asi que render (que emite todos) equivale a solo warnings.
        vx::render_diagnostics(
            std::cerr, cr.diagnostics,
            vx::parse_diag_format(result["diag-format"].as<std::string>()));

        // si --vx-base fue especificado y es != 0, parchear el
        // texto .vel para reemplazar el @IniAddress(0x0000000000000000)
        // generado por defecto por el ir_emitter por @IniAddress(<base>).
        // Esto desplaza todo el code section a la VA solicitada, evitando
        // solapamiento con el caller cuando este modulo se carga via
        // loadmodule.  Es una solucion tactica; idealmente el ir_emitter
        // tomaria una opcion de base address directamente.
        //
        // ADEMAS: insertar `@InitPc(main)` antes del @Module(...) para que
        // el linker compute start_pc = absolute_addr_of_main = base +
        // offset(main) = base + 0 (main es siempre el primer label en
        // codigo Vesta).  Sin esto, start_pc queda en 0 y loadmodule ejecuta
        // codigo del caller en vez del plugin.
        if (vx_base_addr != 0) {
            const std::string from = "@IniAddress(0x0000000000000000)";
            char buf[64];
            std::snprintf(buf, sizeof(buf), "@IniAddress(0x%016llX)",
                          static_cast<unsigned long long>(vx_base_addr));
            std::string to = buf;
            size_t pos = cr.vel_text.find(from);
            if (pos != std::string::npos) {
                cr.vel_text.replace(pos, from.size(), to);
                vesta::scout() << "[vx] @IniAddress patched -> " << to << "\n";
            } else {
                std::cerr << "[vx] aviso: no se encontro @IniAddress(0x0...) "
                             "para parchear con --vx-base\n";
            }
            // Insertar @InitPc(<base>) NUMERICO antes del @Module(...).  El
            // assembler procesa anotaciones single-pass y `main` no esta
            // definido todavia cuando @InitPc se evalua, asi que usamos el
            // valor absoluto (= base, ya que main es siempre el primer label
            // en codigo Vesta y la seccion code tiene @Align(0x1000) que se
            // alinea con la base hex que pasa el usuario).
            const std::string mod_marker = "@Module(";
            size_t mod_pos = cr.vel_text.find(mod_marker);
            if (mod_pos != std::string::npos) {
                char ipbuf[64];
                std::snprintf(ipbuf, sizeof(ipbuf), "@InitPc(0x%llX)\n\n",
                              static_cast<unsigned long long>(vx_base_addr));
                cr.vel_text.insert(mod_pos, ipbuf);
                vesta::scout()
                    << "[vx] @InitPc(0x" << std::hex << vx_base_addr << std::dec
                    << ") insertado (start_pc = base address)\n";
            } else {
                std::cerr << "[vx] aviso: no se encontro @Module(...) para "
                             "insertar @InitPc\n";
            }
            // Convertir el `hlt` final del main del modulo en `ret` para que
            // sea LLAMABLE via callvm desde loadmod del caller.  Por defecto
            // main de Vesta termina con `leave\nhlt` (convencion entry-point);
            // un plugin necesita main RET-able para que el push de return
            // address en loadmod resulte en flujo de vuelta al caller.
            // El standalone execution del plugin no funciona tras esta
            // conversion (RET pop'ea garbage del stack).  Aceptamos esta
            // limitacion: los plugins no se ejecutan standalone.
            const std::string main_ret_marker =
                "main_ret:\n    leave\n    hlt\n";
            const std::string main_ret_repl = "main_ret:\n    leave\n    ret\n";
            size_t hlt_pos = cr.vel_text.find(main_ret_marker);
            if (hlt_pos != std::string::npos) {
                cr.vel_text.replace(hlt_pos, main_ret_marker.size(),
                                    main_ret_repl);
                vesta::scout() << "[vx] main_ret hlt -> ret (modo plugin: "
                                  "callable via loadmod)\n";
            } else {
                std::cerr << "[vx] aviso: no se encontro 'main_ret: leave "
                             "hlt' para convertir a ret\n";
            }
        }

        // Diagramas: cada flag activo produce un archivo .mmd o .dot segun
        // el formato escogido.  Mermaid reconocido por VS Code / GitHub /
        // mermaid.live.  Graphviz se renderiza con `dot -Tsvg foo.dot -o
        // foo.svg`.
        auto write_diagram = [&](const std::string &content,
                                 const std::string &suffix) -> bool {
            if (content.empty()) return true; // no se solicito; no es error
            std::string base =
                out_prefix.empty() ? copts.module_name : out_prefix;
            std::string path = base + suffix;
            std::ofstream ofs(path);
            if (!ofs.is_open()) {
                std::cerr << "[diagram] No se puede escribir: " << path << "\n";
                return false;
            }
            ofs << content;
            vesta::scout() << "[diagram] generado: " << path << "\n";
            return true;
        };
        if (emit_mermaid) {
            if (diag_vx && !write_diagram(cr.mermaid_ast, ".ast.mmd"))
                return EXIT_FAILURE;
            if (diag_ir_pre && !write_diagram(cr.mermaid_ir_pre, ".ir.pre.mmd"))
                return EXIT_FAILURE;
            if (diag_ir_post &&
                !write_diagram(cr.mermaid_ir_post, ".ir.post.mmd"))
                return EXIT_FAILURE;
            if (diag_vel && !write_diagram(cr.mermaid_vel, ".vel.mmd"))
                return EXIT_FAILURE;
        }
        if (emit_graphviz) {
            if (diag_vx && !write_diagram(cr.graphviz_ast, ".ast.dot"))
                return EXIT_FAILURE;
            if (diag_ir_pre &&
                !write_diagram(cr.graphviz_ir_pre, ".ir.pre.dot"))
                return EXIT_FAILURE;
            if (diag_ir_post &&
                !write_diagram(cr.graphviz_ir_post, ".ir.post.dot"))
                return EXIT_FAILURE;
            if (diag_vel && !write_diagram(cr.graphviz_vel, ".vel.dot"))
                return EXIT_FAILURE;
        }
        if (emit_html) {
            // Paginas HTML interactivas autocontenidas: abrir en el navegador.
            if (diag_vx && !write_diagram(cr.html_ast, ".ast.html"))
                return EXIT_FAILURE;
            if (diag_ir_pre && !write_diagram(cr.html_ir_pre, ".ir.pre.html"))
                return EXIT_FAILURE;
            if (diag_ir_post &&
                !write_diagram(cr.html_ir_post, ".ir.post.html"))
                return EXIT_FAILURE;
            if (diag_vel && !write_diagram(cr.html_vel, ".vel.html"))
                return EXIT_FAILURE;
        }

        // (El dump --vx-emit-ir se escribe mas arriba, antes del bloque
        // `if (aot_mode)`, para cubrir tambien el AOT que retorna antes.)

        // Fase 4 interop C: escribir el header C publico (<output>.h) si
        // --emit-header esta activo.  Se hace ANTES del bloque --port (que
        // termina con return) para que `--port c --emit-header` produzca
        // ambos: el .c con las definiciones y el .h con las declaraciones.
        if (copts.emit_header && !cr.header_text.empty()) {
            const std::string h_path = out_prefix.empty()
                                           ? (copts.module_name + ".h")
                                           : (out_prefix + ".h");
            std::ofstream ofs_h(h_path);
            if (!ofs_h.is_open()) {
                std::cerr << "[header] No se puede escribir: " << h_path
                          << "\n";
                return EXIT_FAILURE;
            }
            ofs_h << cr.header_text;
            vesta::scout() << "[header] C generado: " << h_path << " ("
                           << cr.header_text.size() << " bytes)\n";
        }

        // Si --port=<lang> esta activo, escribir el codigo fuente generado
        // y terminar (no compilar a .velb).  El usuario lo compila con su
        // toolchain nativa (gcc/clang/javac/node/etc).  La extension se
        // deriva del target.
        if (!copts.port_target.empty()) {
            std::string ext = ".c"; // default; futuros: .java, .js
            if (copts.port_target == "c") ext = ".c";
            // (mas casos cuando agreguemos backends)
            std::string port_path = out_prefix.empty()
                                        ? (copts.module_name + ext)
                                        : (out_prefix + ext);
            std::ofstream ofs_port(port_path);
            if (!ofs_port.is_open()) {
                std::cerr << "[port] No se puede escribir: " << port_path
                          << "\n";
                return EXIT_FAILURE;
            }
            ofs_port << cr.port_text;
            vesta::scout() << "[port] " << copts.port_target
                           << " generado: " << port_path << " ("
                           << cr.port_text.size() << " bytes)\n";
            for (const auto &w : cr.port_warnings) {
                std::cerr << "[port] warning: " << w << "\n";
            }
            return EXIT_SUCCESS;
        }

        /* 5. El `.vel` intermedio: se queda EN MEMORIA salvo que se pida.
         *
         * Antes se volcaba a disco SIEMPRE y la linea de abajo lo volvia a
         * leer: un viaje de ida y vuelta por el disco con un texto que
         * acabamos de producir.  Medido sobre 24k lineas, esa E/S eran 0,271 s
         * de 7,75 -- el 3,5% de compilar -- y ademas dejaba un fichero de
         * 331.696 lineas que nadie habia pedido.
         *
         * El camino de la cache de macros ya se habia pasado a memoria; este
         * se habia quedado atras.
         *
         * El nombre se conserva aunque no se abra nada: los diagnosticos del
         * ensamblador lo citan. */
        const std::string vel_path = out_prefix.empty()
                                         ? (copts.module_name + ".vel")
                                         : (out_prefix + ".vel");
        std::string vel_texto;
        // Con --vx-debug va `// @file <vx_path>` delante, para que el lexer
        // del .vel-to-.velb se lo pase al linker (Context::debug_source_file).
        if (copts.emit_debug) vel_texto = "// @file " + vx_path + "\n";
        vel_texto += cr.vel_text;

        if (emit_only) {
            std::ofstream ofs(vel_path);
            if (!ofs.is_open()) {
                std::cerr << "[vx] No se puede escribir: " << vel_path << "\n";
                return EXIT_FAILURE;
            }
            ofs << vel_texto;
            ofs.close();
            vesta::scout() << "[vx] .vel generado: " << vel_path << "\n";
        }

        /* Reparto del coste del frontend.  La construccion ya decia lo que
         * tardaban ensamblar y enlazar, pero de la mitad delantera -- la que
         * crece con el tamano del fuente -- no decia nada, asi que "por que
         * tarda tanto en compilar" no tenia respuesta sin instrumentar a mano.
         *
         * `comprobar` es la suma de analisis y tipos: es lo que tarda en salir
         * un diagnostico, que es la pregunta que se hace quien esta editando.
         * Sale de la construccion normal, sin un modo aparte que pedir. */
        {
            const auto &tf = cr.tiempos;
            /* Un proyecto y un fichero suelto no se reparten igual: en el
             * primero el trabajo esta en resolver el grafo y compilar cada
             * modulo, y las fases de un unico fuente no aplican.  Se dice lo
             * que corresponde en cada caso en vez de imprimir ceros. */
            /* En su propio ambito para que se vuelque ANTES del desglose por
             * pase: el desglose explica el `optimizar` de esta linea, y leerlo
             * antes que ella no ayuda. */
            {
                auto linea = vesta::scout();
                if (tf.resolver_us > 0 || tf.modulos_us > 0) {
                    linea << "[vx] frontend: resolver " << tf.resolver_us
                          << " us"
                          << " | modulos " << tf.modulos_us << " us"
                          << " | optimizar " << tf.optimizar_us << " us"
                          << " | emitir " << tf.emitir_us << " us"
                          << "   (total " << tf.total_us() << " us)\n";
                } else {
                    linea << "[vx] frontend: analisis " << tf.analisis_us
                          << " us"
                          << " | tipos " << tf.tipos_us << " us"
                          << " | bajada " << tf.bajada_us << " us"
                          << " | optimizar " << tf.optimizar_us << " us"
                          << " | emitir " << tf.emitir_us << " us"
                          << "   (comprobar " << tf.comprobar_us()
                          << " us, total " << tf.total_us() << " us)\n";
                }
            }
            /* Y el reparto DENTRO de optimizar.  Un solo numero de "optimizar"
             * no deja arreglar nada: un pase que se lleva el 90 % se lee igual
             * que veinte repartiendoselo.  Se ensenan los que pesan, no todos,
             * para que la linea siga siendo legible -- y con cuantas veces
             * corrio cada uno, que un pase caro por lento y otro caro por
             * repetirse se arreglan de formas distintas. */
            const auto pases = ir::tiempos_de_pases();
            long long total_pases = 0;
            for (const auto &q : pases)
                total_pases += q.us;
            if (total_pases > 0) {
                /* La calibracion, a la vista: se descuenta el coste de medir, y
                 * una cifra mas fina que la resolucion del reloj no significa
                 * nada.  Ensenarla evita creerse un numero que el instrumento
                 * no puede dar. */
                const auto cal = util::calibracion_del_cronometro();
                auto lp = vesta::scout();
                lp << "[vx] optimizar por pase:";
                int mostrados = 0;
                for (const auto &q : pases) {
                    /* Lo que no llega al 1 % del reparto no explica nada y solo
                     * alarga la linea. */
                    if (q.us * 100 < total_pases || mostrados >= 6) break;
                    lp << " " << q.nombre << " " << q.us << " us x" << q.veces
                       << (++mostrados < 6 ? " |" : "");
                }
                lp << "   (" << pases.size() << " pases, " << total_pases
                   << " us, " << ir::vueltas_punto_fijo() << " vueltas, ";
                /* Solo si paso: rendirse a medias es una averia, y una averia
                 * que no ocurre no tiene por que ocupar sitio en la linea. */
                if (ir::fixpoint_truncations() > 0)
                    lp << ir::fixpoint_truncations()
                       << " SIN CONVERGER (codigo peor), ";
                lp << ir::visitas_a_funcion() << " visitas; reloj "
                   << cal.fuente << " de " << cal.resolucion_ns
                   << " ns, medir cuesta " << cal.coste_ns << " ns)\n";
            }
            /* Y donde se concentra: el reparto por pase dice cual es caro, este
             * dice si lo es por igual en todas las funciones o por una sola.
             * Son dos averias distintas -- una se arregla haciendo el pase mas
             * barato, la otra mirando como crece con el tamano -- y sin
             * separarlas se ataca a ciegas.  Va el tamano al lado por eso. */
            const auto porfn = ir::tiempos_por_funcion();
            if (!porfn.empty() && total_pases > 0) {
                auto lf = vesta::scout();
                lf << "[vx] optimizar, donde se concentra:";
                for (size_t i = 0; i < porfn.size() && i < 4; ++i) {
                    if (porfn[i].us * 100 < total_pases) break;
                    lf << " " << porfn[i].pase << "@" << porfn[i].funcion << " "
                       << porfn[i].us << " us x" << porfn[i].veces << " ("
                       << porfn[i].instrucciones << " instr)"
                       << (i + 1 < 4 ? " |" : "");
                }
                lf << "\n";
            }
            nlohmann::json jf;
            if (!pases.empty()) {
                /* En el volcado de maquina van TODOS, que ahi no molesta la
                 * longitud y es lo que permite comparar dos compilaciones. */
                nlohmann::json jp = nlohmann::json::object();
                for (const auto &q : pases)
                    jp[q.nombre] = {{"us", q.us}, {"veces", q.veces}};
                jf["pases"] = jp;
            }
            jf["analisis_us"] = tf.analisis_us;
            jf["tipos_us"] = tf.tipos_us;
            jf["bajada_us"] = tf.bajada_us;
            jf["emitir_us"] = tf.emitir_us;
            jf["resolver_us"] = tf.resolver_us;
            jf["modulos_us"] = tf.modulos_us;
            jf["optimizar_us"] = tf.optimizar_us;
            jf["comprobar_us"] = tf.comprobar_us();
            jf["frontend_total_us"] = tf.total_us();
            std::cout << "\n__VESTA_TIMES_FRONTEND__ " << jf.dump() << "\n";
        }

        /* Y a `.velb` DESDE MEMORIA, sin releer nada.
         *
         * `--vx-emit-only` ya NO corta aqui: pedir el `.vel` no deberia
         * obligar a compilar dos veces para tener tambien el `.velb`.  La
         * bandera pasa a significar "ademas, escribeme el .vel", no "y para".
         *
         * Opcion W: el IR pre-serializado va al linker para que se embeba en
         * la seccion @c @ir del `.velb` v3. */
        int rc = asm_multi_process::run_worker_from_source(
            std::move(vel_texto), vel_path, out_prefix,
            /*skip_preprocessor=*/true,
            /*keep_labels=*/(result.count("keep-labels") > 0),
            /*ir_section_bytes=*/&cr.ir_section_bytes,
            /*emit_map=*/(result.count("emit-map") > 0));

        // Se deja constancia de que grafo explica ESTE artefacto, bajo un
        // identificador sacado de su contenido.  Es el ultimo eslabon: sin el,
        // el grafo esta emitido pero nadie puede pedirlo a partir del programa
        // que se esta ejecutando.  Se hace aqui y no al compilar porque el
        // identificador no existe hasta que el fichero existe.
        if (rc == EXIT_SUCCESS && !cr.vxdbg_artifact_map.empty()) {
            vx::publish_vxdbg_artifact(out_prefix + ".velb",
                                       cr.vxdbg_artifact_map, cr.vxdbg_span_map,
                                       copts.vxdbg_dir);

            /* Y AQUI, nunca antes: el almacen se recoge solo cuando le hace
             * falta, pero los nodos que esta compilacion acaba de emitir no
             * estan vivos hasta la publicacion de arriba.  Recoger en medio los
             * daria por muertos y los borraria -- precisamente los del programa
             * que se acaba de compilar.
             *
             * Cuando no toca recoger, esto solo cuenta los ficheros de un
             * directorio; el recorrido, que es lo que cuesta, unicamente ocurre
             * al pasarse del umbral (~1 de cada 500 compilaciones). */
            vxdbg::maintain_store(copts.vxdbg_dir.empty()
                                      ? vx::default_vxdbg_dir()
                                      : copts.vxdbg_dir);
        }

        //  M5.B: persistir el .velb final al project cache si
        // (a) el compile usa imports (compile_vx_project tiene
        // dep_paths populated), (b) el link fue exitoso, y (c) el cache
        // esta enabled.
        /* Se guarda tambien SIN imports.  Antes se exigian, y por eso un
         * fichero suelto no tenia cache: recompilarlo sin tocarlo costaba lo
         * mismo que la primera vez.  Medido en el banco, frio 205 ms ->
         * caliente 193, un 1,06x que no era la cache rindiendo poco sino la
         * cache apagada.  Un fichero sin dependencias es MAS facil de cachear,
         * no menos: su unica dependencia es el mismo. */
        if (rc == EXIT_SUCCESS && project_cache_enabled) {
            /* El fuente raiz entra SIEMPRE como dependencia -- un fichero
             * suelto depende de si mismo y de nada mas --, y con el lo que el
             * preprocesador haya leido.  Sin esto ultimo, tocar un `#include`
             * no invalidaria nada. */
            std::vector<std::string> deps_extra_cache = vpp_included_files;
            deps_extra_cache.push_back(canonical_root);

            const std::string velb_path = out_prefix + ".velb";
            std::ifstream vf(velb_path, std::ios::binary | std::ios::ate);
            if (vf.is_open()) {
                const std::streamsize sz = vf.tellg();
                vf.seekg(0, std::ios::beg);
                std::vector<uint8_t> velb_bytes(
                    static_cast<size_t>(sz < 0 ? 0 : sz));
                if (sz > 0) {
                    vf.read(reinterpret_cast<char *>(velb_bytes.data()), sz);
                }
                vf.close();
                if (!velb_bytes.empty())
                    guardar_cache_de_proyecto(pc_path, opts_hash, diag_hash,
                                              donde, cr, copts.emit_debug,
                                              velb_bytes, project_cache_verbose,
                                              deps_extra_cache);
            }
        }

        /*  MC.4: probe del ComptimeRuntime (activable via env var
         * VESTA_COMPTIME_PROBE=1).  Tras producir el .velb, lo carga
         * en una @c ComptimeRuntime para validar que el pipeline
         * bytecode-in-memory -> Loader -> symbol_table -> macro_entry_pc
         * funciona end-to-end.  Imprime stats y los nombres de macros
         * resueltos.  Cero impacto si el env var no esta seteado. */
        if (rc == EXIT_SUCCESS) {
            if (util::flag_on(util::FlagId::ComptimeProbe)) {
                const std::string velb_path = out_prefix + ".velb";
                std::ifstream f(velb_path, std::ios::binary);
                if (f) {
                    std::vector<uint8_t> bytes(
                        (std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
                    f.close();
                    vx::ComptimeRuntime ctr;
                    const bool loaded =
                        ctr.load_macros_from_bytes(std::move(bytes));
                    std::cerr << "[mc-probe] load_macros_from_bytes -> "
                              << (loaded ? "OK" : "FAIL") << "\n";
                    std::cerr << "[mc-probe] is_initialized -> "
                              << (ctr.is_initialized() ? "true" : "false")
                              << "\n";
                    std::cerr << "[mc-probe] registered_macro_count -> "
                              << ctr.registered_macro_count() << "\n";
                    /* Listar nombres + PCs para demo. */
                    auto names = ctr.list_registered_macros();
                    for (const auto &p : names) {
                        std::cerr << "[mc-probe]   " << p.first << " @ 0x"
                                  << std::hex << p.second << std::dec << "\n";
                    }
                    /*  MC.5: intentar invocar el PRIMER macro a
                     * nivel funcion (filtrar sufijos internos del
                     * lowering: `_entry_`, `_if_`, `_ret`, `_while_`,
                     * `_for_`, `_then_`, `_else_`, `_merge_`). */
                    const std::pair<std::string, uint64_t> *first_fn = nullptr;
                    auto is_internal_label = [](const std::string &n) {
                        static const char *suffixes[] = {
                            "_entry_", "_if_",   "_ret",    "_while_", "_for_",
                            "_then_",  "_else_", "_merge_", "_loop_"};
                        for (const char *suf : suffixes) {
                            if (n.find(suf) != std::string::npos) return true;
                        }
                        return false;
                    };
                    for (const auto &p : names) {
                        if (p.first.find("__macro_") != 0) continue;
                        if (is_internal_label(p.first)) continue;
                        if (!first_fn) first_fn = &p;
                    }
                    if (!first_fn) {
                        std::cerr << "[mc-probe] no se encontro macro "
                                     "top-level invocable\n";
                    } else {
                        std::cerr
                            << "[mc-probe] invoke target: " << first_fn->first
                            << " @ 0x" << std::hex << first_fn->second
                            << std::dec << "\n";
                        /* MC.7: invocar el macro varias veces como
                         * @c string y mostrar el contenido devuelto. */
                        for (int iter = 1; iter <= 3; ++iter) {
                            std::string s_out;
                            const bool ok = ctr.invoke_string_macro(
                                first_fn->first, /*args=*/{}, s_out);
                            std::cerr << "[mc-probe] invoke#" << iter << " -> "
                                      << (ok ? "OK" : "FAIL") << "  string=\""
                                      << s_out << "\"\n";
                        }
                        std::cerr << "[mc-probe] call_count -> "
                                  << ctr.call_count() << "\n";
                    }

                    /*  MC.8: shadow_validate -- replay las
                     * expectaciones que el TypeChecker capturo durante
                     * la evaluacion AST de cada @Macro, invocando via
                     * VM, y comparando los strings.  Cualquier mismatch
                     * indica un bug en lowering del macro a IR (o en el
                     * AST evaluator).  Cero coste si no hay expectacioes. */
                    if (!cr.macro_expectations.empty()) {
                        for (const auto &e : cr.macro_expectations) {
                            ctr.record_expectation(e.macro_name, e.args,
                                                   e.expected_str, e.src_loc);
                        }
                        std::vector<vx::ComptimeRuntime::ShadowMismatch> report;
                        const size_t mismatches = ctr.shadow_validate(report);
                        std::cerr << "[mc-shadow] expectations="
                                  << cr.macro_expectations.size()
                                  << " validated=" << report.size()
                                  << " mismatches=" << mismatches << "\n";
                        for (const auto &m : report) {
                            std::cerr << "[mc-shadow]   "
                                      << (m.match ? "OK   " : "FAIL ")
                                      << m.macro_name << " @ " << m.src_loc
                                      << "  (" << m.reason << ")";
                            if (!m.match) {
                                std::cerr << "  expected=\"" << m.expected
                                          << "\"  got=\"" << m.got << "\"";
                            }
                            std::cerr << "\n";
                        }
                    } else {
                        std::cerr << "[mc-shadow] sin expectaciones (no hay "
                                     "@Macros con args literales)\n";
                    }
                }
            }
        }

        /* Si el ensamblado fallo, DECIRLO.  Se comprobaba `rc` solo para los
         * caminos de exito y se devolvia tal cual: la orden terminaba sin
         * binario y sin una palabra, y desde fuera no habia forma de distinguir
         * eso de un exito.  Es el mismo silencio que el bloque de ensamblador
         * sin cuerpo, y sale igual de caro: un caso de la suite que falla
         * ("no produjo .velb") sin nada que explique por que. */
        if (rc != EXIT_SUCCESS) {
            vx::Diagnostic d;
            d.level = vx::DiagLevel::ERR;
            d.code = "VXA053";
            d.args.push_back(vx_path);
            d.args.push_back(std::to_string(rc));
            d.loc.file = vx_path;
            vx::print_diagnostic(std::cerr, d);
        }
        return rc;
    }

    // Compilar un archivo .vel a .velb
    // vm.exe --build src/main.vel -o main.velb
    if (result.count("build")) {
        return asm_multi_process::run_worker(
            result["build"].as<std::string>(), out_prefix,
            /*skip_preprocessor=*/false,
            /*keep_labels=*/(result.count("keep-labels") > 0),
            /*ir_section_bytes=*/nullptr,
            /*emit_map=*/(result.count("emit-map") > 0));
    }

    // Abrir el REPL interactivo VestaShell (--interprete)
    if (result.count("interprete")) {
        vsh::VshInterpreter interp;
        // ARGV vacio o con [""]
        std::vector<std::string> empty_argv = {""};
        interp.set_argv(empty_argv);
        interp.run_interactive();
        return EXIT_SUCCESS;
    }

    // Ejecutar un fichero VestaShell directamente sin abrir el REPL
    // vm.exe --script mi_script.vsh [args extra para el script...]
    if (result.count("script")) {
        const std::string &vsh_path = result["script"].as<std::string>();

        // Construir ARGV: [vsh_path, args_posicionales_extra...]
        std::vector<std::string> script_args;
        script_args.push_back(vsh_path);
        if (result.count("positional")) {
            for (const auto &a :
                 result["positional"].as<std::vector<std::string>>()) {
                script_args.push_back(a);
            }
        }

        try {
            vsh::VshInterpreter interp;   // sin callback REPL
            interp.set_argv(script_args); // <--- AQUI lo importante
            interp.exec_file(vsh_path);
        } catch (const vsh::VshRuntimeError &e) {
            std::cerr << "[script] Error en " << vsh_path;
            if (e.line > 0) std::cerr << ":" << e.line;
            std::cerr << ": " << e.what() << "\n";
            return EXIT_FAILURE;
        } catch (const vsh::VshParseError &e) {
            std::cerr << "[script] Error de sintaxis en " << vsh_path;
            if (e.line > 0) std::cerr << ":" << e.line;
            std::cerr << ": " << e.what() << "\n";
            return EXIT_FAILURE;
        } catch (const std::exception &e) {
            std::cerr << "[script] " << e.what() << "\n";
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Ejecutar un archivo .velb en la VM
    // vm.exe --run program.velb
    if (result.count("run")) {
        const std::string &velb_path = result["run"].as<std::string>();
        size_t num_schedulers = result["schedulers"].as<size_t>();

        try {
            Timer t_total_run;
            Timer t_construct;
            runtime::ManageVM mgr(nullptr, 0);
            runtime::VM *vm = mgr.loader.create_vm_instance(num_schedulers);
            if (!vm) {
                std::cerr << "Error: no se pudo crear la instancia de VM\n";
                return EXIT_FAILURE;
            }
            const long long ns_construct = t_construct.ns();

            // aplicar configuracion distribuida si el usuario paso algun flag
            // --dist-*
            bool has_dist = result.count("dist-port") > 0 ||
                            result.count("dist-discover") > 0 ||
                            result.count("dist-add-node") > 0 ||
                            result.count("dist-tls") > 0 ||
                            result.count("dist-name") > 0 ||
                            result.count("dist-token") > 0 ||
                            result.count("dist-node-id") > 0;
            if (has_dist) apply_dist_config(vm, result);

            //  M.sandbox (orden critico): pre-activar `sandbox_active`
            // ANTES de load_executable si las caps seran restringidas.
            // load_executable hace el eager-compile de main, cuyo guard de
            // seguridad consulta sandbox_active; si el flag se seteara solo
            // DESPUES (al aplicar exe.caps mas abajo), el eager-compile veria
            // sandbox_active=false -> JIT-compilaria main saltandose el check
            // de capabilities -> bypass del sandbox bajo JIT.
            if (result.count("vx-caps")) {
                const std::string cs = result["vx-caps"].as<std::string>();
                if (!cs.empty() && !::loader::parse_caps(cs).unrestricted()) {
                    mgr.loader.sandbox_active = true;
                }
            }

            Timer t_load;
            runtime::ProcessVM *proc =
                mgr.loader.load_executable(*vm, velb_path);
            if (!proc) {
                std::cerr << "Error: no se pudo cargar el ejecutable\n";
                return EXIT_FAILURE;
            }
            //  M.sandbox: aplicar @c --vx-caps al modulo cargado.
            // El primer Executable del pool es el que acabamos de cargar.
            if (result.count("vx-caps") && !mgr.loader.executables.empty()) {
                const std::string caps_str =
                    result["vx-caps"].as<std::string>();
                if (!caps_str.empty()) {
                    auto &exe = *mgr.loader.executables.front();
                    exe.caps = ::loader::parse_caps(caps_str);
                    // Activar el sandbox solo si las caps son restringidas;
                    // asi check_cap_at_pc paga overhead unicamente cuando hay
                    // un sandbox real en juego.
                    if (!exe.caps.unrestricted()) {
                        mgr.loader.sandbox_active = true;
                    }
                    std::cerr << "[sandbox] modulo principal con caps: "
                              << ::loader::caps_to_string(exe.caps) << "\n";
                }
            }
            const long long ns_load = t_load.ns();

            // Argumentos del script Vesta.  Convencion: el path del .velb es
            // el "argv[0]" implicito del programa; los positionals que el
            // usuario pasa tras `--run prog.velb` son args[0..N-1] desde el
            // punto de vista del programa Vesta (mismo modelo que VSH).  Los
            // builtins Vesta `args_count()` y `args_get(i)` los exponen via
            // los opcodes getargc/getarg.
            if (result.count("positional")) {
                vm->script_args =
                    result["positional"].as<std::vector<std::string>>();
            }

            vm->make_ready(proc->pid);

            // Servidor de depuracion opcional (--debug-port).  Se
            // instancia ANTES de vm.start() para que los clientes ya
            // puedan conectarse antes de que el primer proceso comience.
            // El Debugger es heap-allocado y se libera al exit del scope
            // (RAII via unique_ptr).  Pone has_hooks=true en cada
            // scheduler para activar el slow path con FSM completa que
            // invoca on_before_exec antes de cada instruccion.
            //
            // Sin --debug-port, el unique_ptr queda vacio y el coste
            // runtime es exactamente cero: ningun scheduler tiene
            // has_hooks activo y el fast path se ejecuta sin checks.
            std::unique_ptr<debug::Debugger> dbg;
            if (result.count("debug-port")) {
                uint16_t dbg_port = result["debug-port"].as<uint16_t>();
                if (dbg_port == 0) dbg_port = debug::DBG_DEFAULT_PORT;
                dbg = std::make_unique<debug::Debugger>(*vm);
                if (!dbg->start(dbg_port)) {
                    std::cerr << "Warning: no se pudo iniciar el servidor "
                                 "de depuracion en puerto "
                              << dbg_port << "; continuando sin debugger.\n";
                    dbg.reset();
                } else {
                    vm->debugger = dbg.get();
                    for (auto &sched : vm->schedulers) {
                        sched->has_hooks = true;
                    }
                    // Pausa el proceso main ANTES de su primera
                    // instruccion: sin esto, programas cortos podrian
                    // terminar antes de que el cliente conecte.  El
                    // usuario tipicamente conecta el cliente VSH, hace
                    // `attach 0`, pone breakpoints (si los necesita), y
                    // emite `continue 0` para arrancar la ejecucion.
                    dbg->pause_at_start(proc->pid.local_pid);
                    vesta::scout() << "[debugger] servidor TCP escuchando en "
                                   << "puerto " << dbg_port << "\n";
                    vesta::scout() << "[debugger] proceso main pausado al "
                                   << "inicio (pid=" << proc->pid.local_pid
                                   << "); conecta el cliente y emite "
                                   << "'continue " << proc->pid.local_pid
                                   << "' para arrancar.\n";
                }
            }

            Timer t_run;
            Timer t_start_phase;
            vm->start();
            const long long ns_start = t_start_phase.ns();

            Timer t_poll;
            // en lugar de polling con sleep_for(1ms)
            // (granularity ~15.6ms en Windows), bloquear con condition
            // variable.  El ultimo scheduler que ponga vm_running=false
            // notifica done_cv y main desbloquea inmediatamente.
            {
                std::unique_lock<std::mutex> lk(vm->done_mtx);
                vm->done_cv.wait(lk, [&] {
                    return !vm->vm_running.load(std::memory_order_acquire);
                });
            }
            const long long ns_poll = t_poll.ns();

            long long elapsed_ns = t_run.ns();

            Timer t_stop;
            vm->stop();
            const long long ns_stop = t_stop.ns();
            const long long ns_total_run = t_total_run.ns();

            // PGO producer: junto al '.vprof', escribir '<path>.lines' (perfil
            // de branches por linea, consumido al recompilar).  La VM sigue
            // viva aqui -> el debug_info (seccion DVBG, requiere --vex-debug)
            // mapea cada PC a su linea fuente.
            if (result.count("profile")) {
                const std::string bp =
                    result["profile"].as<std::string>() + ".lines";
                runtime::profile::profile_write_branch_lines(
                    bp, [&](uint64_t pc) -> uint32_t {
                        for (const auto &exe : mgr.loader.executables) {
                            if (!exe || !exe->debug_info) continue;
                            auto info = exe->debug_info->lookup_line(
                                static_cast<uint32_t>(pc));
                            if (info.found && info.line > 0) return info.line;
                        }
                        return 0;
                    });
            }

            if (result.count("stats")) {
                long long elapsed_ms = elapsed_ns / 1'000'000;
                long long elapsed_us = elapsed_ns / 1'000;

                /* Tiempo de COMPILACION del JIT.  Se imprime junto al resto
                 * porque el reloj de pared los mezcla: el JIT compila mientras
                 * el programa corre. Sin este desglose no se puede distinguir
                 * "el codigo generado es mejor" de "la compilacion tardo
                 * menos", que es justo lo que hace falta para juzgar una
                 * optimizacion del backend. */
                jit::print_jit_timing(jit::JitTiming::detail_enabled());
                if (jit::JitTiming::instance().count() && elapsed_ns > 0) {
                    /* El reparto se hace contra (compilar + ejecutar), NO
                     * contra
                     * @c elapsed_ns: ese reloj mide la EJECUCION, y la
                     * compilacion queda fuera -- dividir por el daba
                     * porcentajes de miles por ciento.  Un ratio solo significa
                     * algo si numerador y denominador miden lo mismo. */
                    const double comp_ms =
                        jit::JitTiming::instance().total_ns() / 1e6;
                    const double run_ms = elapsed_ns / 1e6;
                    vesta::scout()
                        << "[jit] reparto: compilar " << comp_ms
                        << " ms + ejecutar " << run_ms << " ms  -> compilar = "
                        << (100.0 * comp_ms / (comp_ms + run_ms))
                        << "% del trabajo" << std::endl;
                }

                uint64_t total_instrs = 0;
                uint64_t total_jit_instrs = 0;
                uint64_t active_time_ns = 0;
                uint64_t jit_time_ns = 0;
                for (const auto &sched : vm->schedulers) {
                    total_instrs += sched->profiler_instr_counter;
                    /* JIT instrs: cada metodo JIT-eated incrementa el contador
                     * con N IR-instrs al entrar (proxy de bytecode instrs).
                     * Combinarlo con interp counter da MIPS reales. */
                    total_jit_instrs += sched->profiler_jit_instr_counter;
                    active_time_ns += sched->time_exec + sched->time_decode;
                    jit_time_ns += sched->time_jit;
                }
                /* active_time incluye el JIT time tambien (solo cuenta cuando
                 * el JIT-method retorna).  Si JIT corre durante interp
                 * dispatch, el time_jit ya esta incluido en time_exec via el
                 * wrapper. */

                for (auto &sched : vm->schedulers) {
                    vesta::scout()
                        << "[Scheduler " << sched->id_scheduler
                        << "] Estados de procesos: "
                        << sched->ready_queue.size() << " "
                        << sched->processes.size() << " " << sched->is_waiting
                        << " " << sched->should_kill // indica si la instancia
                                                     // debe morir.
                        << std::endl;
                    vesta::scout() << sched->to_string() << std::endl;
                    for (auto &p : sched->processes) {
                        vesta::scout() << "\t[Process " << p->pid.local_pid
                                       << "] Estados de procesos: "
                                       << runtime::vm_state_to_str(p->state)
                                       << " " << std::endl;
                        vesta::scout() << p->to_string() << std::endl;
                    }
                }

                /* TOTAL instructions = interp + JIT.  El interp counter
                 * se incrementa por instr ejecutada (profiler_instr_counter
                 * sin multiplicar - antes habia un fudge de *256 que ya no
                 * aplica).  El JIT counter se incrementa por N (IR instrs
                 * del metodo) al ENTRY de cada invocacion JIT-eated. */
                const uint64_t total_combined = total_instrs + total_jit_instrs;
                // sin hooks time_decode/time_exec son 0; usar wall time como
                // base
                uint64_t mips_base_ns =
                    active_time_ns > 0 ? active_time_ns : (uint64_t)elapsed_ns;
                double mips = total_combined > 0 && mips_base_ns > 0
                                  ? (total_combined * 1000.0) / mips_base_ns
                                  : 0.0;

                vesta::scout() << "\n=== RUN STATS ===\n";
                vesta::scout()
                    << "Wall time:     " << elapsed_ns << " ns  (" << elapsed_us
                    << " us, " << elapsed_ms << " ms)\n";
                if (active_time_ns > 0) {
                    vesta::scout()
                        << "Tiempo activo: " << active_time_ns << " ns  ("
                        << active_time_ns / 1000 << " us, "
                        << active_time_ns / 1'000'000 << " ms)\n";
                }
                vesta::scout() << "Instrucciones: " << total_combined
                               << "  (interp=" << total_instrs
                               << ", JIT=" << total_jit_instrs << ")\n";
                if (jit_time_ns > 0) {
                    vesta::scout() << "JIT time:      " << jit_time_ns
                                   << " ns  (" << jit_time_ns / 1000 << " us, "
                                   << jit_time_ns / 1'000'000 << " ms)\n";
                    if (total_jit_instrs > 0) {
                        const double jit_mips =
                            (total_jit_instrs * 1000.0) / jit_time_ns;
                        vesta::scout() << "JIT MIPS:      " << jit_mips << "\n";
                    }
                }
                vesta::scout()
                    << "MIPS:          " << mips
                    << (active_time_ns > 0 ? "" : "  (wall time)") << "\n";
                vesta::scout() << "\n=== OVERHEAD BREAKDOWN ===\n";
                vesta::scout()
                    << "VM construct:    " << ns_construct / 1000 << " us\n";
                vesta::scout()
                    << "load_executable: " << ns_load / 1000 << " us\n";
                vesta::scout() << "vm.start:        " << ns_start / 1000
                               << " us  (lanzar threads)\n";
                vesta::scout() << "wait until done: " << ns_poll / 1000
                               << " us  (cv wait)\n";
                vesta::scout() << "vm.stop:         " << ns_stop / 1000
                               << " us  (join threads)\n";
                vesta::scout()
                    << "Total --run:     " << ns_total_run / 1000 << " us\n";
            }

            /* --jit-stats: imprimir contadores del JIT al final.
             * Independiente de --stats; util para auditar % de funciones
             * JIT-eatables en programas reales. */
            if (jit_stats_requested) {
                vesta::scout() << "\n=== JIT STATS ===\n";
                vesta::scout() << jit::get_jit_stats_summary() << "\n";
            }
        } catch (const std::exception &e) {
            std::cerr << "Error al ejecutar " << velb_path << ": " << e.what()
                      << "\n";
            return EXIT_FAILURE;
        }
        /* Si el programa murio por un fallo que nadie capturo, el proceso sale
         * con el codigo que le corresponde y no con cero.  Salir con cero tras
         * reventar es mentirle a quien lo llamo -- y quien lo llama suele ser
         * un guion o una integracion continua que se lo cree. */
        if (const int fatal_rc = runtime::last_fatal_exit_code())
            return fatal_rc;
        return EXIT_SUCCESS;
    }

    // BUG FIX: flags no reconocidos.  cxxopts corre con
    // allow_unrecognised_options (para pass-through de args a scripts), asi que
    // un flag mal escrito (`--vx`, `--vex`, combinaciones invalidas) NO
    // abortaba el parse -> el programa caia SILENCIOSAMENTE al REPL interactivo
    // (que bloquea en stdin).  Si llegamos aqui es que ningun modo se
    // selecciono; si el usuario paso algun token que EMPIEZA con `-` (un flag),
    // es un flag desconocido -> error claro + usage en lugar de abrir el REPL.
    // El REPL legitimo sin args (o `--interprete`) no pasa flags -> no se ve
    // afectado.
    {
        std::vector<std::string> bad_flags;
        for (const auto &u : result.unmatched()) {
            if (!u.empty() && u[0] == '-') bad_flags.push_back(u);
        }
        if (!bad_flags.empty()) {
            std::cerr << "[error] flag(s) no reconocido(s):";
            for (const auto &f : bad_flags)
                std::cerr << " " << f;
            std::cerr << "\n        usa 'vesta --help' para ver las opciones "
                         "validas.\n";
            return EXIT_FAILURE;
        }
    }

    cli::Config cfg;
    cfg.history_file = "my_vm_history.txt";
    cfg.history_max = 1000;
    cfg.prompt = "vesta> ";
    cfg.multiline_end = ";;";

    cli::VestaViewManager vm(cfg);

    vm.set_execute_callback([](const std::string &cmd) {
        auto fut = runtime::run_command_async(cmd);
        std::thread([f = std::move(fut)]() mutable {
            try {
                auto out = f.get();
                if (!out.empty()) vesta::scout() << out << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Runtime error: " << e.what() << std::endl;
            }
        }).detach();
    });

    vm.run();

    return EXIT_SUCCESS;
}
