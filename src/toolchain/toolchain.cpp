/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file toolchain/toolchain.cpp
 * @brief Implementacion del driver de compilacion reutilizable (ver el header).
 */

#include "toolchain/toolchain.h"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <unordered_map>

#if defined(_WIN32)
#include <io.h>
#define VESTA_DUP _dup
#define VESTA_DUP2 _dup2
#define VESTA_FILENO _fileno
#define VESTA_NULLDEV "NUL"
#else
#include <unistd.h>
#define VESTA_DUP dup
#define VESTA_DUP2 dup2
#define VESTA_FILENO fileno
#define VESTA_NULLDEV "/dev/null"
#endif

#include "toolchain/aot_build.h"         // vesta::tc::compile_aot
#include "util/assembler_multiprocess.h" // asm_multi_process::run_worker
#include "vx/compiler.h"                 // vx::compile_vx_source / _project

// Algunos headers arrastrados (windows.h y utilidades vendored) definen ERROR
// y ERR como macros; colisionan con los enumeradores.  Se limpian aqui, tras
// los includes, para poder nombrar los enums con seguridad.
#ifdef ERROR
#undef ERROR
#endif
#ifdef ERR
#undef ERR
#endif

namespace vesta {
namespace tc {

namespace {

/// @brief Traduce el nivel de diagnostico del frontend al del toolchain.
DiagLevel map_level(vx::DiagLevel lvl) {
    switch (lvl) {
    case vx::DiagLevel::ERR: return DiagLevel::Error;
    case vx::DiagLevel::WARN: return DiagLevel::Warning;
    default: return DiagLevel::Note;
    }
}

/// @brief Copia los diagnosticos del @c CompileResult al vector de salida.
/// @return true si hay al menos un error.
bool collect_diags(const vx::CompileResult &res, std::vector<Diag> &out) {
    bool had_error = false;
    for (const auto &d : res.diagnostics.all()) {
        Diag e;
        e.level = map_level(d.level);
        e.line = d.loc.line;
        e.column = d.loc.column;
        e.message = d.message;
        e.file = d.loc.file();
        if (e.level == DiagLevel::Error) had_error = true;
        out.push_back(std::move(e));
    }
    return had_error;
}

/// @brief Redirige temporalmente la salida estandar (fd 1) a el dispositivo
///        nulo mientras vive el objeto, restaurandola en el destructor.
///
/// El ensamblado/linkado (@c run_worker) imprime progreso en stdout con
/// @c std::cout / printf; un consumidor que use stdout como canal de protocolo
/// (el LSP) debe silenciarlo.  Un simple swap de @c std::cout::rdbuf no basta
/// porque hay escrituras via C stdio; por eso se redirige el descriptor de
/// fichero a bajo nivel (captura cout + printf + fwrite).
class StdoutSilencer {
  public:
    explicit StdoutSilencer(bool active) : active_(active) {
        if (!active_) return;
        std::fflush(stdout);
        saved_ = VESTA_DUP(VESTA_FILENO(stdout));
        null_ = std::fopen(VESTA_NULLDEV, "w");
        if (null_ && saved_ != -1)
            VESTA_DUP2(VESTA_FILENO(null_), VESTA_FILENO(stdout));
    }
    ~StdoutSilencer() {
        if (!active_) return;
        std::fflush(stdout);
        if (saved_ != -1) {
            VESTA_DUP2(saved_, VESTA_FILENO(stdout));
#if defined(_WIN32)
            _close(saved_);
#else
            close(saved_);
#endif
        }
        if (null_) std::fclose(null_);
    }
    StdoutSilencer(const StdoutSilencer &) = delete;
    StdoutSilencer &operator=(const StdoutSilencer &) = delete;

  private:
    bool active_;
    int saved_ = -1;
    std::FILE *null_ = nullptr;
};

/// @brief Deriva el prefijo de salida a partir del @c input si no se dio @c -o.
///        Quita la extension @c .vx (o cualquier extension) del nombre.
std::string derive_output(const std::string &input) {
    // Quedarse con todo hasta el ultimo '.', respetando separadores de ruta.
    size_t slash = input.find_last_of("/\\");
    size_t dot = input.find_last_of('.');
    if (dot != std::string::npos && (slash == std::string::npos || dot > slash))
        return input.substr(0, dot);
    return input;
}

} // namespace

CompileResponse compile(const CompileRequest &req) {
    CompileResponse resp;

    if (req.input.empty()) {
        resp.message = "no se indico fichero de entrada";
        return resp;
    }
    const bool aot = (req.mode == ExecMode::AOT);

    // 1) Leer el fuente del raiz (o usar el overlay del buffer en memoria).
    std::string source = req.source_overlay;
    if (source.empty() && !req.is_project) {
        std::ifstream ifs(req.input, std::ios::binary);
        if (!ifs.is_open()) {
            resp.message = "no se pudo abrir el fichero: " + req.input;
            return resp;
        }
        source.assign(std::istreambuf_iterator<char>(ifs),
                      std::istreambuf_iterator<char>());
    }

    // 2) Mapear la peticion a las opciones del frontend.
    vx::CompileOptions opts;
    opts.module_name = req.module_name.empty() ? "main" : req.module_name;
    opts.emit_debug = req.debug;
    if (req.opt_level >= 0) opts.opt_level = req.opt_level;
    opts.instrument_mode = req.instrument;
    // AOT usa POO nativa (clases sin registry); VM/JIT producen el mismo .velb.
    opts.native_poo = aot;

    // Silenciar stdout durante toda la compilacion si el consumidor lo pide
    // (el LSP, para no romper su canal JSON-RPC).  Vive hasta el final de la
    // funcion; los diagnosticos NO se pierden (se recolectan del CompileResult,
    // no se leen de stdout).
    StdoutSilencer silencer(req.quiet);

    // 3) Frontend: .vx -> .vel (+ IR embebido) + diagnosticos.
    const auto t0 = std::chrono::steady_clock::now();
    vx::CompileResult cr;
    if (req.is_project) {
        std::unordered_map<std::string, std::string> overlay;
        const std::unordered_map<std::string, std::string> *ovl = nullptr;
        if (!req.source_overlay.empty()) {
            overlay[req.input] = req.source_overlay;
            ovl = &overlay;
        }
        const std::vector<std::string> *paths =
            req.search_paths.empty() ? nullptr : &req.search_paths;
        cr = vx::compile_vx_project(req.input, opts, ovl, paths);
    } else {
        cr = vx::compile_vx_source(source, req.input, opts);
    }
    const auto t1 = std::chrono::steady_clock::now();
    resp.frontend_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());

    // 4) Recolectar diagnosticos; abortar si hubo errores.
    if (collect_diags(cr, resp.diagnostics)) {
        resp.message = "la compilacion produjo errores";
        return resp;
    }

    const std::string out_prefix =
        req.output.empty() ? derive_output(req.input) : req.output;

    // 4-AOT) Modo AOT: emitir el artefacto nativo (.exe/.o/.so/.bin) con el
    // emisor extraido; no se escribe .vel/.velb.  compile_aot imprime su
    // progreso con std::cout, ya silenciado por el StdoutSilencer si quiet.
    if (aot) {
        const int rc = compile_aot(cr, opts, out_prefix, req.aot);
        if (rc != 0) {
            resp.message = "la emision AOT nativa fallo";
            return resp;
        }
        resp.ok = true;
        resp.output_path = out_prefix; // el emisor decide la extension real
        return resp;
    }

    // 5) Escribir el .vel intermedio junto al artefacto de salida.
    const std::string vel_path = out_prefix + ".vel";
    {
        std::ofstream ofs(vel_path);
        if (!ofs.is_open()) {
            resp.message =
                "no se pudo escribir el .vel intermedio: " + vel_path;
            return resp;
        }
        if (opts.emit_debug) ofs << "// @file " << req.input << "\n";
        ofs << cr.vel_text;
    }

    /* 6) Ensamblar + linkar -> .velb (embebe el IR en la seccion @ir).
     *
     * Desde la fuente EN MEMORIA.  El `.vel` se sigue escribiendo porque es un
     * artefacto que se pide (`--vx-emit-only`) y sirve para depurar, pero
     * ensamblar ya no lo lee: el texto es el que acaba de salir del emisor, y
     * volver a leerlo del disco era el mismo contenido dando un viaje.
     *
     * El prologo `// @file` que se escribe al fichero cuando hay info de
     * depuracion tiene que ir tambien en lo que se ensambla, o la seccion de
     * depuracion del `.velb` se queda sin el nombre del fuente. */
    std::string vel_src;
    if (opts.emit_debug) vel_src = "// @file " + req.input + "\n";
    vel_src += cr.vel_text;
    const int rc = asm_multi_process::run_worker_from_source(
        std::move(vel_src), vel_path, out_prefix,
        /*skip_preprocessor=*/true,
        /*keep_labels=*/req.keep_labels,
        /*ir_section_bytes=*/&cr.ir_section_bytes,
        /*emit_map=*/req.emit_map);
    if (rc != 0) {
        resp.message = "el ensamblado/linkado del .velb fallo (run_worker)";
        return resp;
    }

    resp.ok = true;
    resp.output_path = out_prefix + ".velb";
    return resp;
}

} // namespace tc
} // namespace vesta
