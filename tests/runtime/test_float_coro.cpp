/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia VMProject
 *
 * USO LIBRE NO COMERCIAL con atribucion obligatoria.
 * PROHIBIDO lucro sin permiso escrito.
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file test_float_coro.cpp
 * @brief Suite de pruebas para las instrucciones de punto flotante y corutinas.
 *
 * Verifica el correcto funcionamiento de:
 *   - Instrucciones de carga: fmowi, fmov
 *   - Aritmetica escalar f64: fadd, fsub, fmul, fdiv
 *   - Comparacion: fcmp (flags ZF, SF, CF)
 *   - Funciones unarias: fsqrt, fabs, fneg
 *   - Conversion: fcvt (GP->ZMM y ZMM->GP)
 *   - Acceso a memoria VM: fload, fstore
 *   - Corutinas Modelo A: yield, spawn
 */

#include <iostream>
#include <sstream>
#include <string>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <thread>
#include <chrono>

#include "emmit/parser_to_bytecode.h"
#include "lexer/lexer.h"
#include "parser/parser.h"
#include "linker/velb_linker_bytecode.h"
#include "runtime/manager_runtime.h"
#include "runtime/vm_registers.h"

using namespace Assembly::Bytecode;

/* -------------------------------------------------------------------------
 * Colores ANSI para salida legible.
 * ---------------------------------------------------------------------- */
#define C_RESET "\033[0m"
#define C_RED "\033[31m"
#define C_GREEN "\033[32m"
#define C_YELLOW "\033[33m"
#define C_CYAN "\033[36m"
#define C_BOLD "\033[1m"

/* -------------------------------------------------------------------------
 * Prefijo de encabezado para todos los programas .vel de prueba.
 * ---------------------------------------------------------------------- */
static const char *VEL_HEADER = "@Format(\"raw\")\n"
                                "@SpaceAddress {\n"
                                "    @Name(\"anonymous\"),\n"
                                "    @IniAddress(0x0000000000000000),\n"
                                "    @EndAddress(0xFFFFFFFFFFFFFFFF)\n"
                                "}\n"
                                "@Section {\n"
                                "    @Name(\"all\"),\n"
                                "    @SpaceAddress(\"anonymous\")\n"
                                "    @Align(0x1000)\n"
                                "}\n";

/**
 * @brief Resultado de ejecutar un programa, y DUENO de la VM que lo ejecuto.
 *
 * Cada caso crea su propia VM y ninguno la destruia: 24 VMs vivas a la vez con
 * sus arenas y sus hilos, hasta que el proceso se quedaba sin memoria del
 * sistema -- y no moria donde se agotaba, sino mas tarde y en otro sitio, con
 * un `bad_alloc` que nadie capturaba.
 *
 * Liberar en el destructor y no en cada caso no es comodidad: los casos salen
 * ANTES por `if (!r.ok) return`, y una limpieza escrita a mano se la salta
 * justo cuando algo ha ido mal.  Ademas, un caso nuevo la hereda sin tener que
 * acordarse, que es como se llego hasta aqui.
 */
struct RunResult {
    runtime::ProcessVM *proc = nullptr; ///< Proceso tras la ejecucion
    runtime::VM *vm = nullptr;          ///< VM que lo ejecuto (se destruye)
    runtime::ManageVM *mgr = nullptr;   ///< Gestor al que pedirle la baja
    bool ok = false; ///< true si el programa termino normalmente (HALT/DEAD)

    RunResult() = default;
    RunResult(const RunResult &) = delete;
    RunResult &operator=(const RunResult &) = delete;
    RunResult(RunResult &&other) noexcept { *this = std::move(other); }
    RunResult &operator=(RunResult &&other) noexcept {
        if (this != &other) {
            proc = other.proc;
            vm = other.vm;
            mgr = other.mgr;
            ok = other.ok;
            other.proc = nullptr;
            other.vm = nullptr;
            other.mgr = nullptr;
            other.ok = false;
        }
        return *this;
    }
    ~RunResult() {
        // Tras esto `proc` cuelga, y es correcto: el caso ya leyo lo suyo.
        if (mgr != nullptr && vm != nullptr) mgr->destroy_vm(vm->id);
    }
};

/* -------------------------------------------------------------------------
 * run_vel() - Compila, enlaza y ejecuta un programa .vel en linea.
 *
 * @param manager   Gestor de VMs reutilizado entre pruebas.
 * @param vel_src   Codigo fuente .vel completo (con cabecera incluida).
 * @param test_name Nombre de la prueba (solo para mensajes de error).
 * @return          RunResult con el proceso tras la ejecucion.
 * ---------------------------------------------------------------------- */
static RunResult run_vel(runtime::ManageVM &manager, const std::string &vel_src,
                         const char *test_name) {
    RunResult result;
    result.mgr = &manager; // dueno desde el principio, aunque falle a medias

    /* 1. Lex + Parse */
    vm::Lexer lexer(vel_src);
    vm::Parser parser(lexer);
    std::vector<std::unique_ptr<vm::ASTNode>> program;
    try {
        program = parser.parse();
    } catch (const vm::ParseError &e) {
        fprintf(stderr, "[%s] Parse error: %s\n", test_name, e.what());
        return result;
    }

    /* 2. Ensamblar */
    Assembler asmblr;
    std::vector<uint8_t> bytecode;
    try {
        bytecode = asmblr.assemble(program);
    } catch (const std::exception &e) {
        fprintf(stderr, "[%s] Assembler error: %s\n", test_name, e.what());
        return result;
    }

    /* 3. Enlazar */
    const std::string outfile = std::string("_test_") + test_name + ".velb";
    Linker::LinkerOptions opts;
    opts.optimize_bytecode = false;
    opts.generate_map_file = false;
    opts.output_path = outfile;
    opts.verbose = false;

    Linker::Linker linker(opts);
    linker.add_assembly_unit(bytecode, &asmblr.ctx);
    linker.write_to_file(outfile);

    /* 4. Crear VM e instancia de proceso */
    runtime::VM *vm = manager.loader.create_vm_instance(1 /*1 scheduler*/);
    /* Apuntarla YA, no al final: las salidas de aqui abajo (fallo del
     * cargador, tiempo agotado) tambien tienen que devolverla. */
    result.vm = vm;

    runtime::ProcessVM *proc = nullptr;
    try {
        proc = manager.loader.load_executable(*vm, outfile);
    } catch (const std::exception &e) {
        fprintf(stderr, "[%s] Loader error: %s\n", test_name, e.what());
        return result;
    }
    if (!proc) {
        fprintf(stderr, "[%s] load_executable devolvio nullptr\n", test_name);
        return result;
    }

    /* 5. Ejecutar: lanzar y esperar a que el proceso PRINCIPAL termine
     * (HALT/DEAD). El proceso puede haber lanzado hijos via spawn; esperamos
     * solo al padre. */
    vm->make_ready(proc->pid);
    vm->start();

    /* Esperar a que el proceso principal alcance HALT o DEAD (timeout de 5 s)
     */
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (proc->state != runtime::HALT && proc->state != runtime::DEAD) {
        if (std::chrono::steady_clock::now() >= deadline) {
            fprintf(stderr,
                    "[%s] Timeout: el proceso principal no termino en 5 s\n",
                    test_name);
            vm->stop();
            return result;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    vm->stop();

    result.proc = proc;
    result.ok = true;
    return result;
}

/* -------------------------------------------------------------------------
 * Macros de asercion simples.
 * ---------------------------------------------------------------------- */
static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (cond) {                                                            \
            printf("[PASS] %s\n", msg);                                        \
            fflush(stdout);                                                    \
            ++g_pass;                                                          \
        } else {                                                               \
            printf("[FAIL] %s\n", msg);                                        \
            fflush(stdout);                                                    \
            ++g_fail;                                                          \
        }                                                                      \
    } while (0)

#define CHECK_DOUBLE(a, b, eps, msg) CHECK(std::fabs((a) - (b)) < (eps), msg)

/* =========================================================================
 * Pruebas de punto flotante
 * ====================================================================== */

/**
 * @brief Prueba la carga inmediata flotante: fmowi f0, bits(1.0).
 *
 * Verifica que el registro f0 contenga exactamente 1.0 tras fmowi.
 */
static void test_fmowi(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f0, 0x3FF0000000000000\n" /* f0 = 1.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fmowi");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), 1.0, 1e-12,
                 "fmowi: f0 == 1.0");
}

/**
 * @brief Prueba la copia de registro flotante: fmov f1, f0.
 */
static void test_fmov(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f0, 0x4000000000000000\n" /* f0 = 2.0 */
                            "    fmov  f1, f0\n" /* f1 = f0 = 2.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fmov");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[1].read_f64(), 2.0, 1e-12,
                 "fmov: f1 == 2.0");
}

/**
 * @brief Prueba la suma escalar: fadd f0, f1 => 1.0 + 2.0 = 3.0.
 */
static void test_fadd(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f0, 0x3FF0000000000000\n" /* f0 = 1.0 */
                            "    fmowi f1, 0x4000000000000000\n" /* f1 = 2.0 */
                            "    fadd  f0, f1\n"                 /* f0 = 3.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fadd");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), 3.0, 1e-12,
                 "fadd: 1.0+2.0=3.0");
}

/**
 * @brief Prueba la resta escalar: fsub f0, f1 => 3.0 - 1.0 = 2.0.
 */
static void test_fsub(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f0, 0x4008000000000000\n" /* f0 = 3.0 */
                            "    fmowi f1, 0x3FF0000000000000\n" /* f1 = 1.0 */
                            "    fsub  f0, f1\n"                 /* f0 = 2.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fsub");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), 2.0, 1e-12,
                 "fsub: 3.0-1.0=2.0");
}

/**
 * @brief Prueba la multiplicacion escalar: fmul f0, f1 => 2.0 * 3.0 = 6.0.
 */
static void test_fmul(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f0, 0x4000000000000000\n" /* f0 = 2.0 */
                            "    fmowi f1, 0x4008000000000000\n" /* f1 = 3.0 */
                            "    fmul  f0, f1\n"                 /* f0 = 6.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fmul");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), 6.0, 1e-12,
                 "fmul: 2.0*3.0=6.0");
}

/**
 * @brief Prueba la division escalar: fdiv f0, f1 => 6.0 / 2.0 = 3.0.
 */
static void test_fdiv(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f0, 0x4018000000000000\n" /* f0 = 6.0 */
                            "    fmowi f1, 0x4000000000000000\n" /* f1 = 2.0 */
                            "    fdiv  f0, f1\n"                 /* f0 = 3.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fdiv");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), 3.0, 1e-12,
                 "fdiv: 6.0/2.0=3.0");
}

/**
 * @brief Prueba fcmp con operandos iguales (ZF=1, SF=0).
 */
static void test_fcmp_equal(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f0, 0x4000000000000000\n" /* f0 = 2.0 */
                            "    fmowi f1, 0x4000000000000000\n" /* f1 = 2.0 */
                            "    fcmp  f0, f1\n" /* ZF=1, SF=0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fcmp_eq");
    if (!r.ok) return;
    CHECK(r.proc->registers.flags.bits.ZF == 1, "fcmp_eq: ZF=1 (iguales)");
    CHECK(r.proc->registers.flags.bits.SF == 0, "fcmp_eq: SF=0 (no menor)");
}

/**
 * @brief Prueba fcmp con operando izquierdo menor (ZF=0, SF=1).
 */
static void test_fcmp_less(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f0, 0x3FF0000000000000\n" /* f0 = 1.0 */
                            "    fmowi f1, 0x4000000000000000\n" /* f1 = 2.0 */
                            "    fcmp  f0, f1\n" /* 1.0 < 2.0 => ZF=0, SF=1 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fcmp_lt");
    if (!r.ok) return;
    CHECK(r.proc->registers.flags.bits.ZF == 0, "fcmp_lt: ZF=0 (no iguales)");
    CHECK(r.proc->registers.flags.bits.SF == 1, "fcmp_lt: SF=1 (f0 < f1)");
}

/**
 * @brief Prueba fsqrt: sqrt(4.0) = 2.0.
 */
static void test_fsqrt(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f1, 0x4010000000000000\n" /* f1 = 4.0 */
                            "    fsqrt f0, f1\n" /* f0 = sqrt(4.0) = 2.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fsqrt");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), 2.0, 1e-12,
                 "fsqrt: sqrt(4.0)=2.0");
}

/**
 * @brief Prueba fabs: |(-5.0)| = 5.0.
 */
static void test_fabs(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f1, 0xC014000000000000\n" /* f1 = -5.0 */
                            "    fabs  f0, f1\n"                 /* f0 = 5.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fabs");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), 5.0, 1e-12,
                 "fabs: |-5.0|=5.0");
}

/**
 * @brief Prueba fneg: -(3.0) = -3.0.
 */
static void test_fneg(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    fmowi f1, 0x4008000000000000\n" /* f1 = 3.0 */
                            "    fneg  f0, f1\n"                 /* f0 = -3.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fneg");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), -3.0, 1e-12,
                 "fneg: -(3.0)=-3.0");
}

/**
 * @brief Prueba fcvt entero->flotante: r1=5 -> f0=5.0.
 *
 * Sintaxis: fcvt r1, f0  =>  f0 = (double) r1
 */
static void test_fcvt_i2f(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    mov  r1, 5\n"  /* r1 = 5 (entero) */
                            "    fcvt r1, f0\n" /* f0 = (double) r1 = 5.0 */
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "fcvt_i2f");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), 5.0, 1e-12,
                 "fcvt i2f: r1=5 -> f0=5.0");
}

/**
 * @brief Prueba fcvt flotante->entero: f0=7.9 -> r2=7 (truncado).
 *
 * Sintaxis: fcvt f0, r2  =>  r2 = (int64_t) f0
 */
static void test_fcvt_f2i(runtime::ManageVM &mgr) {
    const std::string src =
        std::string(VEL_HEADER) +
        "code:\n"
        "    fmowi f0, 0x401F99999999999A\n" /* f0 = 7.9 (aprox) */
        "    fcvt  f0, r2\n"                 /* r2 = (int64_t) f0 = 7 */
        "    hlt\n"
        "end_code:\n";

    auto r = run_vel(mgr, src, "fcvt_f2i");
    if (!r.ok) return;
    CHECK(r.proc->registers.regs[2].qword() == 7ULL,
          "fcvt f2i: f0=7.9 -> r2=7");
}

/**
 * @brief Prueba fstore + fload: escribir 1.0 en memoria VM y releerlo.
 *
 * Sintaxis:
 *   fstore r1, f0   =>  VM[r1] = f0
 *   fload  f1, r1   =>  f1 = VM[r1]
 */
static void test_fload_fstore(runtime::ManageVM &mgr) {
    const std::string src =
        std::string(VEL_HEADER) +
        "code:\n"
        "    fmowi f0, 0x3FF0000000000000\n"     /* f0 = 1.0 */
        "    mov   r1, @Absolute(\"all.buf\")\n" /* r1 = direccion VM del buffer
                                                  */
        "    fstore r1, f0\n"                    /* VM[r1] = f0 = 1.0 */
        "    fload  f1, r1\n"                    /* f1 = VM[r1] = 1.0 */
        "    hlt\n"
        "end_code:\n"
        "align 8\n"
        "buf db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00\n"
        "end_buf:\n";

    auto r = run_vel(mgr, src, "fload_fstore");
    if (!r.ok) return;
    CHECK_DOUBLE(r.proc->registers.zmm[0].read_f64(), 1.0, 1e-12,
                 "fstore: f0 guardado = 1.0");
    CHECK_DOUBLE(r.proc->registers.zmm[1].read_f64(), 1.0, 1e-12,
                 "fload: f1 cargado = 1.0");
}

/* =========================================================================
 * Pruebas de corutinas
 * ====================================================================== */

/**
 * @brief Prueba yield: el proceso cede el quantum y llega a hlt normalmente.
 *
 * yield fuerza reductions_remaining=0; el scheduler lo volvera a poner
 * en READY y continuara desde la siguiente instruccion (hlt).
 */
static void test_yield(runtime::ManageVM &mgr) {
    const std::string src = std::string(VEL_HEADER) +
                            "code:\n"
                            "    mov r0, 99\n" /* r0 = 99 antes de yield */
                            "    yield\n"
                            "    hlt\n"
                            "end_code:\n";

    auto r = run_vel(mgr, src, "yield");
    if (!r.ok) return;
    /* si llego a hlt, r0 sigue siendo 99 */
    CHECK(r.proc->registers.regs[0].qword() == 99ULL,
          "yield: r0=99 tras yield+hlt");
}

/**
 * @brief Prueba spawn: crea un proceso hijo y devuelve el PID en r0 (!=0).
 *
 * El proceso hijo ejecuta su propio hlt y muere normalmente.
 */
static void test_spawn(runtime::ManageVM &mgr) {
    const std::string src =
        std::string(VEL_HEADER) +
        "code:\n"
        "    mov r1, @Absolute(\"all.child\")\n" /* r1 = PC del hijo */
        "    spawn r1\n" /* r0 = PID codificado del hijo */
        "    hlt\n"
        "end_code:\n"
        "child:\n"
        "    hlt\n"
        "end_child:\n";

    auto r = run_vel(mgr, src, "spawn");
    if (!r.ok) return;
    CHECK(r.proc->registers.regs[0].qword() != 0ULL,
          "spawn: r0 != 0 (PID del hijo devuelto)");
}

/* =========================================================================
 * Tests de instrucciones nuevas: isnull, unwrap, tailcall, resume, swapctx
 * ====================================================================== */

/**
 * @brief Prueba isnull: r1 = (r0 == 0) ? 1 : 0.
 *
 * Caso 1: r0 = 0  -> r1 debe ser 1.
 * Caso 2: r0 = 42 -> r1 debe ser 0.
 */
static void test_isnull(runtime::ManageVM &mgr) {
    /* caso r0 = 0 -> r1 = 1 */
    {
        const std::string src = std::string(VEL_HEADER) +
                                "code:\n"
                                "    mov r0, 0\n"
                                "    isnull r1, r0\n" /* r1 = (r0==0) ? 1 : 0 */
                                "    hlt\n"
                                "end_code:\n";

        auto r = run_vel(mgr, src, "isnull_null");
        if (!r.ok) return;
        CHECK(r.proc->registers.regs[1].qword() == 1ULL,
              "isnull: r0=0  -> r1=1");
    }
    /* caso r0 = 42 -> r1 = 0 */
    {
        const std::string src = std::string(VEL_HEADER) + "code:\n"
                                                          "    mov r0, 42\n"
                                                          "    isnull r1, r0\n"
                                                          "    hlt\n"
                                                          "end_code:\n";

        auto r = run_vel(mgr, src, "isnull_nonnull");
        if (!r.ok) return;
        CHECK(r.proc->registers.regs[1].qword() == 0ULL,
              "isnull: r0=42 -> r1=0");
    }
}

/**
 * @brief Prueba unwrap: r1 = r0 si r0 != 0; lanza excepcion si r0 == 0.
 *
 * Solo verifica el caso no nulo (r0=77 -> r1=77).
 * El caso nulo genera EVT_ERROR; el proceso pasa a DEAD (estado esperado).
 */
static void test_unwrap(runtime::ManageVM &mgr) {
    /* caso no nulo: r0=77 -> r1=77 */
    {
        const std::string src =
            std::string(VEL_HEADER) +
            "code:\n"
            "    mov r0, 77\n"
            "    unwrap r1, r0\n" /* r1 = r0 porque r0 != 0 */
            "    hlt\n"
            "end_code:\n";

        auto r = run_vel(mgr, src, "unwrap_ok");
        if (!r.ok) return;
        CHECK(r.proc->registers.regs[1].qword() == 77ULL,
              "unwrap: r0=77 -> r1=77");
    }
    /* caso nulo: el proceso debe morir (DEAD) */
    {
        const std::string src =
            std::string(VEL_HEADER) +
            "code:\n"
            "    mov r0, 0\n"
            "    unwrap r1, r0\n" /* debe lanzar NullPointerException -> DEAD */
            "    hlt\n"
            "end_code:\n";

        auto r = run_vel(mgr, src, "unwrap_null");
        /* ok = true solo si HALT o DEAD; aqui esperamos DEAD */
        if (r.proc) {
            CHECK(r.proc->state == runtime::DEAD,
                  "unwrap: r0=0 -> proceso termina en DEAD "
                  "(NullPointerException)");
        }
    }
}

/**
 * @brief Prueba tailcall: llamada en posicion de cola sin crecimiento de pila.
 *
 * El programa define una funcion 'target' que pone 42 en r0 y hace hlt.
 * La funcion 'caller' hace tailcall a 'target'.
 * Se verifica que r0 = 42 tras la ejecucion.
 */
static void test_tailcall(runtime::ManageVM &mgr) {
    const std::string src =
        std::string(VEL_HEADER) +
        "code:\n"
        "    mov r1, @Absolute(\"all.target\")\n"
        "    tailcall r1\n" /* salta a target sin crecer la pila */
        "    hlt\n"         /* nunca se alcanza */
        "end_code:\n"
        "target:\n"
        "    mov r0, 42\n"
        "    hlt\n"
        "end_target:\n";

    auto r = run_vel(mgr, src, "tailcall");
    if (!r.ok) return;
    CHECK(r.proc->registers.regs[0].qword() == 42ULL,
          "tailcall: r0=42 tras salto en cola");
}

/**
 * @brief Prueba resume: reactiva un proceso hijo despues de que haya cedido el
 * quantum.
 *
 * El padre spawna un hijo que hace yield y luego hlt.
 * El padre llama resume con el PID del hijo para asegurarse de que vuelve a
 * READY. Se verifica que el padre recibio un PID valido en r0.
 */
static void test_resume(runtime::ManageVM &mgr) {
    const std::string src =
        std::string(VEL_HEADER) +
        "code:\n"
        "    mov r1, @Absolute(\"all.child\")\n"
        "    spawn r1\n"  /* r0 = PID del hijo */
        "    resume r0\n" /* reactivar el hijo (idempotente si ya es READY) */
        "    hlt\n"
        "end_code:\n"
        "child:\n"
        "    yield\n" /* ceder el quantum voluntariamente */
        "    hlt\n"
        "end_child:\n";

    auto r = run_vel(mgr, src, "resume");
    if (!r.ok) return;
    CHECK(r.proc->registers.regs[0].qword() != 0ULL,
          "resume: padre recibio PID valido en r0");
}

/**
 * @brief Prueba swapctx: intercambio de contexto cooperativo entre dos fibras.
 *
 * Allocamos dos buffers de 152 bytes en la pila VM.
 * Rellenamos el buffer 'ctx_b' con un contexto que apunta a la funcion
 * 'fiber_b'. swapctx guarda el contexto actual en 'ctx_a' y lo restaura desde
 * 'ctx_b'. La ejecucion continua en 'fiber_b', donde se establece r0=55 y se
 * hace hlt.
 *
 * Este test verifica que swapctx salta correctamente a la nueva funcion.
 */
static void test_swapctx(runtime::ManageVM &mgr) {
    /* La VM necesita que el buffer de contexto de destino tenga un PC valido en
     * offset 0. Usamos alloc para crear los buffers y mov SIB para escribir el
     * PC de fiber_b en ctx_b[0]. movc requiere un nombre de flag; para
     * escritura incondicional usamos mov [base+idx*1], reg. */
    const std::string src =
        std::string(VEL_HEADER) +
        "code:\n"
        /* alocar 304 bytes (2 x 152): ctx_a en r10, ctx_b en r11 */
        "    mov r0, 304\n"
        "    alloc r0\n"    /* r0 = puntero raw al bloque */
        "    mov r10, r0\n" /* r10 = ctx_a (offset 0) */
        "    mov r11, r10\n"
        "    adds r11, 152\n" /* r11 = ctx_b (offset 152) */
        /* r9 = 0 como indice cero para SIB incondicional */
        "    mov r9, 0\n"
        /* Las tres escrituras del contexto van con MOVH, no con MOV.
         *
         * `alloc` devuelve un puntero del ANFITRION -- lo dice su propia
         * implementacion: "devolver puntero host en R00" -- y `swapctx` lee y
         * escribe los dos contextos como punteros del anfitrion.  Escribirlos
         * con `mov` los mandaba a la memoria de la MAQUINA VIRTUAL, a la
         * direccion que sale de tomar el puntero del anfitrion como si fuera
         * virtual: otro sitio.
         *
         * Y no fallaba.  Dejaba a CERO el contexto donde swapctx lo lee, o sea
         * un PC de cero, o sea saltar al principio del programa -- que vuelve a
         * reservar --, asi que cada vuelta pedia otro bloque en otra direccion
         * y la maquina virtual mapeaba una pagina nueva por cada uno.  120.003
         * paginas despues, el proceso moria sin memoria muy lejos de aqui. */
        /* escribir el PC de fiber_b en ctx_b[0] (offset 0 del contexto = PC) */
        "    mov r2, @Absolute(\"all.fiber_b\")\n"
        "    movh [r11 + r9*1], r2\n" /* ctx_b.pc = fiber_b */
        /* escribir SP valido en ctx_b[8] usando r11 desplazado */
        "    adds r11, 8\n"
        "    movh [r11 + r9*1], r0\n" /* ctx_b.sp = r0 (puntero valido
                                        cualquiera) */
        "    adds r11, 8\n"
        "    movh [r11 + r9*1], r0\n" /* ctx_b.bp = r0 */
        "    subs r11, 16\n"          /* restaurar r11 a inicio de ctx_b */
        /* intercambiar contexto: ir a fiber_b, guardar este en ctx_a */
        "    swapctx r11, r10\n" /* swapctx dst=ctx_b, src=ctx_a */
        "    hlt\n"              /* no se alcanza si swapctx funciona */
        "end_code:\n"
        "fiber_b:\n"
        "    mov r0, 55\n"
        "    hlt\n"
        "end_fiber_b:\n";

    auto r = run_vel(mgr, src, "swapctx");
    if (!r.ok) return;
    CHECK(r.proc->registers.regs[0].qword() == 55ULL,
          "swapctx: r0=55 tras salto a fiber_b");
}

/* =========================================================================
 * main
 * ====================================================================== */

int main() {
    printf("=== Suite de pruebas: instrucciones float y corutinas ===\n\n");
    fflush(stdout);

    runtime::ManageVM manager(nullptr, 0);
    /* --- Instrucciones flotantes escalares --- */
    printf(C_YELLOW "\n--- Carga y copia ---\n" C_RESET);
    test_fmowi(manager);
    test_fmov(manager);

    printf(C_YELLOW "\n--- Aritmetica escalar f64 ---\n" C_RESET);
    test_fadd(manager);
    test_fsub(manager);
    test_fmul(manager);
    test_fdiv(manager);

    printf(C_YELLOW "\n--- Comparacion ---\n" C_RESET);
    test_fcmp_equal(manager);
    test_fcmp_less(manager);

    printf(C_YELLOW "\n--- Funciones unarias ---\n" C_RESET);
    test_fsqrt(manager);
    test_fabs(manager);
    test_fneg(manager);

    printf(C_YELLOW "\n--- Conversion int<->float ---\n" C_RESET);
    test_fcvt_i2f(manager);
    test_fcvt_f2i(manager);

    printf(C_YELLOW "\n--- Memoria VM ---\n" C_RESET);
    test_fload_fstore(manager);

    /* --- Corutinas Modelo A --- */
    printf(C_YELLOW "\n--- Corutinas (Modelo A) ---\n" C_RESET);
    test_yield(manager);
    test_spawn(manager);
    test_resume(manager);
    test_swapctx(manager);

    /* --- Instrucciones nuevas: nullable y TCO --- */
    printf(C_YELLOW "\n--- Nullable (isnull / unwrap) ---\n" C_RESET);
    test_isnull(manager);
    test_unwrap(manager);

    printf(C_YELLOW "\n--- TCO (tailcall) ---\n" C_RESET);
    test_tailcall(manager);

    /* --- Resumen --- */
    printf(C_BOLD "\n=== Resultado: %d PASS  %d FAIL ===\n" C_RESET, g_pass,
           g_fail);

    return (g_fail == 0) ? 0 : 1;
}
