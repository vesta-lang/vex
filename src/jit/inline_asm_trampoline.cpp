/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/inline_asm_trampoline.cpp
 * @brief Implementacion del trampoline de inline-asm para el interprete
 *        ( AS inc.6).  Ver inline_asm_trampoline.h.
 */

#include "util/env_flags.h"
#include "jit/inline_asm_trampoline.h"

#include "jit/code_cache.h"
#include "vx/asm/asm_backend.h"
#include "ffi/virtual_lib_registry.h"  // inc.6: registrar el helper runner
#include "runtime/exception_runtime.h" // parar si el asm no se puede ejecutar
#include "vx/diag/diag_catalog.h" // el fallo se cuenta en el idioma del lector
#include "runtime/proceso_runtime.h" // inc.6: acceso a ProcessVM::asm_ctx + vm_mem

#include <atomic> // emulacion portable del efecto (barrera) sin ensamblador
#include "ir/ssa_ir.h"           // inc.6: IrFunction/IrInstr/IrOp del batch
#include "vx/asm/asm_phys_reg.h" // sustitucion $N -> reg fisico

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <unordered_map>

#if defined(_WIN32)
#include <windows.h> // RtlAddFunctionTable: desenrollado del codigo generado
#endif

namespace jit {

#if defined(_WIN32)
namespace {

/**
 * @brief Describe el prologo del trampoline para que el sistema sepa
 *        desenrollarlo.
 *
 * En Windows de 64 bits el desenrollado NO se hace siguiendo punteros de marco:
 * se hace por TABLAS.  Para cada trozo de codigo, el sistema busca una entrada
 * que diga cuanto ocupa su prologo y que guardo en la pila; si no la encuentra,
 * da el trozo por hoja y supone que en la cima de la pila esta la direccion de
 * retorno.
 *
 * El codigo que genera el compilador en caliente no esta en ninguna tabla,
 * porque las tablas las trae el ejecutable.  Mientras nadie tenga que
 * desenrollar por encima de el, da igual.  Pero un fallo del procesador DENTRO
 * de un bloque de ensamblador se recoge con un salto largo, y un salto largo en
 * Windows ES un desenrollado: el sistema se ponia a caminar la pila, llegaba al
 * trampoline, no encontraba entrada, lo daba por hoja, leia como direccion de
 * retorno lo que hubiera en la cima -- que en mitad del prologo no lo es -- y
 * se llevaba el proceso por delante.  Como lo que hubiera en la cima depende de
 * como quedo la pila, el mismo programa moria o no segun donde estuviera el
 * binario: se reproducia cambiando la LONGITUD DE LA RUTA del ejecutable.
 *
 * Aqui se registra esa entrada.  El prologo son nueve `push` de tamano fijo,
 * asi que se describe una vez y vale para todos los trampolines.
 *
 * La estructura vive en el propio cache de codigo (vida del proceso) porque el
 * sistema guarda el PUNTERO, no una copia.
 */
struct DesenrolladoTrampoline {
    RUNTIME_FUNCTION funcion;
    /* UNWIND_INFO cabecera (4 bytes) + 9 codigos de 2 bytes.  Se escribe a mano
     * porque la definicion de winnt.h lleva un array flexible. */
    uint8_t info[4 + 9 * 2];
};

/// Codigos de operacion del desenrollado (winnt.h no los expone como enum).
enum : uint8_t { UWOP_PUSH_NONVOL = 0, UWOP_ALLOC_SMALL = 2 };

/**
 * @brief Rellena la descripcion del prologo y la registra en el sistema.
 *
 * @param code   Principio del codigo del trampoline (ya copiado y comiteado).
 * @param n      Tamano del codigo en bytes.
 * @param cc     Cache donde alojar la descripcion (misma vida que el codigo).
 * @return true si quedo registrada.
 */
bool registrar_desenrollado(uint8_t *code, size_t n, CodeCache &cc) {
    /* El prologo que emite `build_asm_trampoline`, byte a byte.  Se COMPRUEBA
     * en vez de darlo por hecho: si algun dia cambia, mentirle al desenrollador
     * es peor que no decirle nada, asi que ante la duda no se registra. */
    static const uint8_t kPrologo[] = {
        0x53,       // push rbx
        0x55,       // push rbp
        0x56,       // push rsi
        0x57,       // push rdi
        0x41, 0x54, // push r12
        0x41, 0x55, // push r13
        0x41, 0x56, // push r14
        0x41, 0x57, // push r15
        0x51,       // push rcx  (el que trae ctx en Win64)
    };
    const size_t kPrologoLen = sizeof(kPrologo);
    if (n < kPrologoLen || std::memcmp(code, kPrologo, kPrologoLen) != 0)
        return false;

    auto *d = reinterpret_cast<DesenrolladoTrampoline *>(
        cc.alloc(sizeof(DesenrolladoTrampoline), 16));
    if (d == nullptr) return false;
    std::memset(d, 0, sizeof(*d));

    /* Los codigos van en orden DESCENDENTE de posicion dentro del prologo: el
     * desenrollador los aplica de atras hacia delante.  La posicion de cada uno
     * es la del byte SIGUIENTE a su instruccion. */
    struct Paso {
        uint8_t off, op, info;
    };
    static const Paso kPasos[] = {
        {13, UWOP_ALLOC_SMALL, 0},  // push rcx -> solo devuelve 8 bytes de pila
        {12, UWOP_PUSH_NONVOL, 15}, // push r15
        {10, UWOP_PUSH_NONVOL, 14}, // push r14
        {8, UWOP_PUSH_NONVOL, 13},  // push r13
        {6, UWOP_PUSH_NONVOL, 12},  // push r12
        {4, UWOP_PUSH_NONVOL, 7},   // push rdi
        {3, UWOP_PUSH_NONVOL, 6},   // push rsi
        {2, UWOP_PUSH_NONVOL, 5},   // push rbp
        {1, UWOP_PUSH_NONVOL, 3},   // push rbx
    };
    const uint8_t n_codigos = (uint8_t)(sizeof(kPasos) / sizeof(kPasos[0]));
    d->info[0] = 1;                    // version 1, sin banderas
    d->info[1] = (uint8_t)kPrologoLen; // tamano del prologo
    d->info[2] = n_codigos;            // numero de codigos
    d->info[3] = 0;                    // sin registro de marco
    for (uint8_t i = 0; i < n_codigos; ++i) {
        d->info[4 + i * 2] = kPasos[i].off;
        d->info[4 + i * 2 + 1] =
            (uint8_t)(kPasos[i].op | (kPasos[i].info << 4));
    }

    /* Las direcciones de la tabla son RELATIVAS a una base que elegimos.  Se
     * toma el propio codigo, asi que todos los desplazamientos son pequenos. */
    const DWORD64 base = (DWORD64)(uintptr_t)code;
    d->funcion.BeginAddress = 0;
    d->funcion.EndAddress = (DWORD)n;
    d->funcion.UnwindData = (DWORD)((DWORD64)(uintptr_t)d->info - base);
    return RtlAddFunctionTable(&d->funcion, 1, base) != FALSE;
}

} // namespace
#endif // _WIN32

// =====================================================================
//   AS inc.6: registro global hash(NASM) -> trampoline + helper
//  nativo que el interprete invoca por cada bloque inline-asm.
// =====================================================================

namespace {
std::unordered_map<uint64_t, AsmTrampolineFn> &asm_tramp_map() {
    static std::unordered_map<uint64_t, AsmTrampolineFn> m;
    return m;
}
std::mutex &asm_tramp_mtx() {
    static std::mutex mtx;
    return mtx;
}
} // namespace

void register_inline_asm_trampoline(uint64_t hash, AsmTrampolineFn fn) {
    if (fn == nullptr) return;
    std::lock_guard<std::mutex> lk(asm_tramp_mtx());
    // idempotente: cuerpos asm identicos comparten trampoline.
    asm_tramp_map().emplace(hash, fn);
}

AsmTrampolineFn lookup_inline_asm_trampoline(uint64_t hash) {
    std::lock_guard<std::mutex> lk(asm_tramp_mtx());
    auto it = asm_tramp_map().find(hash);
    return (it == asm_tramp_map().end()) ? nullptr : it->second;
}

/* Helper nativo invocado por el bytecode (calln
 * @Method("vrt:inline_asm_exec")). Convencion (argc SIEMPRE 12, slots no usados
 * = 0): arg0  proc  = ProcessVM* (via getproc) arg1  hash  = FNV-1a del NASM
 * (clave del trampoline) arg2  desc  = phys-id (4 bits) por binding, hasta 8
 * bindings arg3  n     = numero de bindings (<=8) arg4..11    = direcciones VM
 * de los slots (alloca) de cada binding
 *
 * Marshalling: rellena @c vm->asm_ctx[phys] desde el slot VM (in), llama al
 * trampoline (que carga los 16 GP host desde ctx, corre el asm, y los
 * guarda de vuelta a ctx), y escribe @c ctx[phys] al slot VM (out).  Cada
 * binding es in+out (conservador, siempre correcto). */
extern "C" uint64_t vrt_inline_asm_exec(uint64_t proc, uint64_t hash,
                                        uint64_t desc, uint64_t n_u,
                                        uint64_t s0, uint64_t s1, uint64_t s2,
                                        uint64_t s3, uint64_t s4, uint64_t s5,
                                        uint64_t s6, uint64_t s7) {
    auto *vm = reinterpret_cast<runtime::ProcessVM *>(proc);
    if (vm == nullptr) return 0;

    AsmTrampolineFn tramp = lookup_inline_asm_trampoline(hash);
    if (tramp == nullptr) {
        /* El TERCER sitio con el mismo fallo, y lo encontro la prueba del
         * arreglo de los otros dos: se avisaba por la salida de error y se
         * continuaba, asi que un programa cuyo `asm` no se puede ejecutar --
         * porque la VM corre en otra arquitectura, que es el caso que este
         * camino existe para cubrir -- seguia con los valores de antes y
         * devolvia un resultado falso sin que el `catch` del programa llegara a
         * entrar.
         *
         * Aqui no se puede distinguir un bloque que solo ordena la memoria (los
         * efectos no llegan a esta via), asi que se para siempre.  Es lo
         * conservador correcto: parar de mas cuesta un `try`/`catch` explicito,
         * seguir de mas cuesta un resultado equivocado. */
        char msg[192];
        std::snprintf(msg, sizeof(msg),
                      "bloque de ensamblador no ejecutable en esta maquina: no "
                      "hay ensamblador para su ISA, y saltarlo cambiaria el "
                      "resultado");
        runtime::throw_fatal(vm, runtime::FATAL_ILLEGAL_INSTRUCTION, msg);
        return 0;
    }

    const int n = static_cast<int>(n_u);
    const uint64_t slots[8] = {s0, s1, s2, s3, s4, s5, s6, s7};
    uint64_t *ctx = vm->asm_ctx; // host scratch del proceso

    for (int i = 0; i < 16; ++i)
        ctx[i] = 0;
    /* El hueco de cada operando puede vivir en memoria de la maquina virtual o
     * en la del host; el bit 32+i del descriptor dice cual.  Leerlo por la via
     * equivocada daba basura de entrada y tiraba el resultado a la salida. */
    auto es_host = [&](int i) { return (desc >> (32 + i)) & 1ull; };
    /* Cuantos bytes mide cada operando: tres bits en los bits 40..63.  El cero
     * es el banco general, que son ocho.  Sin esto, un operando del banco ancho
     * se movia como si midiera ocho y llegaba a medias -- eso no da error, deja
     * basura dentro, y por eso el ancho se DICE en vez de deducirse del
     * registro (`xmm3`, `ymm3` y `zmm3` son la misma ranura). */
    auto ancho_de = [&](int i) {
        return static_cast<unsigned>((desc >> (40 + i * 3)) & 0x7ull);
    };
    /* Donde vive el valor de un operando dentro del contexto: los del banco
     * general en su ranura directa, los anchos en la zona de detras, que tiene
     * @c kAsmCtxVecQwords por ranura.  Es el mismo reparto que usa la otra via
     * y que espera el trampolin. */
    auto hueco_de = [&](int i, int phys) -> uint8_t * {
        if (ancho_de(i) == 0) return reinterpret_cast<uint8_t *>(&ctx[phys]);
        return reinterpret_cast<uint8_t *>(
            &ctx[vx::kAsmCtxGpSlots + (size_t)phys * vx::kAsmCtxVecQwords]);
    };
    // in-marshalling: hueco -> ctx[phys]
    for (int i = 0; i < n && i < 8; ++i) {
        const int phys = static_cast<int>((desc >> (i * 4)) & 0xF);
        const unsigned bytes = vx::asm_ancho_de_codigo(ancho_de(i));
        uint8_t *dst = hueco_de(i, phys);
        if (es_host(i)) {
            std::memcpy(dst, reinterpret_cast<const void *>(slots[i]), bytes);
        } else {
            vm->vm_mem.read_bytes(slots[i], dst, bytes);
        }
    }
    tramp(ctx); // ejecuta el asm host
    // out-marshalling: ctx[phys] -> hueco
    for (int i = 0; i < n && i < 8; ++i) {
        const int phys = static_cast<int>((desc >> (i * 4)) & 0xF);
        const unsigned bytes = vx::asm_ancho_de_codigo(ancho_de(i));
        const uint8_t *src = hueco_de(i, phys);
        if (es_host(i)) {
            std::memcpy(reinterpret_cast<void *>(slots[i]), src, bytes);
        } else {
            vm->vm_mem.write_bytes(slots[i], src, bytes);
        }
    }
    return 0;
}

/* Ejecuta una ASM_MICRO (asm opaco liftado, SIN operandos de registro) en el
 * interprete, con doble via segun haya ensamblador:
 *
 *   arg0 proc = ProcessVM* (scratch ctx para el trampoline).
 *   arg1 hash = FNV-1a de la plantilla (clave del trampoline nativo).
 *   arg2 eff  = bits de efecto de la DB (bit3 barrera) para la EMULACION.
 *
 * Si existe un trampoline nativo (el loader lo construyo con el ensamblador
 * para el host), se ejecuta la instruccion REAL.  Si NO (host sin ensamblador u
 * otra arch), se EMULA su efecto de forma PORTABLE via los eff bits -> el
 * codigo sigue funcionando en cualquier arch (esta es la ventaja de ASM_MICRO
 * sobre la caja opaca INLINE_ASM, que sin ensamblador no puede hacer NADA). */
extern "C" uint64_t vrt_asm_micro_exec(uint64_t proc, uint64_t hash,
                                       uint64_t eff) {
    AsmTrampolineFn tramp = lookup_inline_asm_trampoline(hash);
    if (tramp != nullptr) {
        // Via nativa (ensamblador presente): ejecuta la instruccion REAL.  Sin
        // operandos de registro -> ctx solo es scratch para el prologo/epilogo
        // generico del trampoline.
        auto *vm = reinterpret_cast<runtime::ProcessVM *>(proc);
        if (vm != nullptr) {
            for (int i = 0; i < 16; ++i)
                vm->asm_ctx[i] = 0;
            tramp(vm->asm_ctx);
        }
        return 0;
    }
    // Via portable (sin ensamblador / otra arch): emular el efecto de la DB.
    if (eff & 0x8u) // barrera de memoria (mfence/lfence/sfence)
        std::atomic_thread_fence(std::memory_order_seq_cst);
    // Sin barrera (pause/nop): no-op.
    return 0;
}

/**
 * @brief Ejecuta una @c ASM_MICRO cuyos operandos son VALORES del programa.
 *
 * El interprete no reparte registros, asi que los valores no estan donde la
 * instruccion los espera: hay que meterlos antes y sacarlos despues.  Es lo
 * mismo que ya se hacia con los bloques opacos, solo que alli los valores se
 * leen de la variable y aqui llegan en una tabla, porque despues de elevar el
 * bloque el dato ya no es "la variable X" sino un valor del IR.
 *
 * Sin esto, cada instruccion corria con los registros a cero y devolvia lo que
 * hiciera al vacio.
 *
 * @param proc ProcessVM actual.
 * @param hash Clave del trampolin (texto ya con sus registros puestos).
 * @param eff Efectos de la base, para emular si no hay ensamblador.
 * @param tabla Direccion, en memoria de la maquina virtual, de @p n huecos de
 *        8 bytes: uno por operando, en el orden de la ficha.
 * @param desc 4 bits por operando con el registro que le toca.
 * @param n Cuantos operandos hay (maximo 8).
 * @return 0.
 */
/**
 * @brief Ejecuta un bloque `asm` leyendo sus operandos DONDE YA ESTAN: en los
 *        registros de la VM.
 *
 * Es la via que sustituye a la tabla.  La otra mueve los valores a la pila para
 * leerlos de ahi y los devuelve al terminar -- dos copias por operando y por
 * bloque -- cuando el valor ya esta en un registro de la VM, y la VM tiene los
 * dos bancos.  Un bloque `asm` no es una frontera que cruzar copiando: es
 * codigo dentro del codigo.
 *
 * @param proc  Proceso (el que devuelve `getproc`).
 * @param hash  FNV-1a del cuerpo ya sustituido: la clave del trampolin.
 * @param eff   Efectos empaquetados del bloque (memoria, flags, barrera).
 * @param locs  Direccion VM de un array de @ref vx::AsmOperandLoc, uno por
 *              operando con valor.
 * @param n     Cuantos operandos.
 */
extern "C" uint64_t vrt_asm_micro_regs(uint64_t proc, uint64_t hash,
                                       uint64_t eff, uint64_t locs0,
                                       uint64_t locs1, uint64_t n) {
    auto *vm = reinterpret_cast<runtime::ProcessVM *>(proc);
    if (vm == nullptr) return 0;
    AsmTrampolineFn tramp = lookup_inline_asm_trampoline(hash);
    if (tramp == nullptr) {
        /* Sin ensamblador se emula lo que se pueda de la base -- una barrera es
         * una barrera en cualquier maquina -- pero una instruccion que CAMBIA
         * valores no: los devolveria sin tocar.  Callarselo seria dar por hecho
         * un trabajo que no se hizo. */
        /* Una barrera SI se puede cumplir sin ensamblador -- es una barrera en
         * cualquier maquina -- asi que un bloque que solo ordena la memoria
         * sigue siendo correcto y se deja pasar. */
        if (eff & 0x8u) std::atomic_thread_fence(std::memory_order_seq_cst);
        if (n != 0) {
            /* Pero un bloque que CAMBIA valores no se puede saltar.  Antes se
             * avisaba por la salida de error y se continuaba con los valores
             * sin tocar: el programa seguia y daba resultados falsos, que es
             * peor que pararse -- nadie lee un aviso de un programa que
             * "funciona".
             *
             * Y este caso no es raro ni teorico: la VM tiene que poder correr
             * en cualquier arquitectura, asi que un `asm` escrito para otra no
             * se puede ejecutar aqui de ninguna forma.  Lo correcto entonces es
             * decirlo y parar; el programa portable elige otro camino con
             * `@Target`, que para eso esta.
             *
             * Es capturable (`try { } catch (FatalError e) { }`), asi que quien
             * quiera seguir puede decidirlo -- explicitamente, no por omision.
             */
            char msg[192];
            std::snprintf(msg, sizeof(msg),
                          "bloque de ensamblador no ejecutable en esta maquina "
                          "(%llu operandos): no hay ensamblador para su ISA, y "
                          "sus valores cambiarian el resultado",
                          (unsigned long long)n);
            runtime::throw_fatal(vm, runtime::FATAL_ILLEGAL_INSTRUCTION, msg);
        }
        return 0;
    }

    const uint64_t kMax = vx::kAsmLocsPerWord * 2;
    const int nops = (int)(n > kMax ? kMax : n);
    uint64_t *ctx = vm->asm_ctx;
    /* El contexto entero: dejar restos de un bloque anterior en las partes que
     * este no escribe seria darle entrada a un valor que nadie le paso. */
    std::memset(ctx, 0, sizeof(vm->asm_ctx));

    auto loc_de = [&](int i) -> uint16_t {
        const uint64_t w = (i < (int)vx::kAsmLocsPerWord) ? locs0 : locs1;
        const int k = i % (int)vx::kAsmLocsPerWord;
        return (uint16_t)((w >> (k * 16)) & 0xFFFFu);
    };

    /* De los registros de la VM al contexto del trampolin.  Sin pila, sin tabla
     * y sin ningun registro reservado para direccionarla: las posiciones vienen
     * en los propios argumentos porque se conocen al compilar. */
    for (int i = 0; i < nops; ++i) {
        const uint16_t p = loc_de(i);
        if ((vx::asm_loc_flags(p) & vx::kAsmLocReads) == 0) continue;
        const uint8_t r = vx::asm_loc_vm_reg(p);
        const uint8_t ph = vx::asm_loc_phys(p);
        if (vx::asm_loc_bank(p) == vx::kAsmBankWide) {
            if (ph >= vx::kAsmCtxVecSlots) continue;
            vm->registers.zmm[r].read_zmm(
                &ctx[vx::kAsmCtxGpSlots + (size_t)ph * vx::kAsmCtxVecQwords]);
        } else {
            if (ph >= vx::kAsmCtxGpSlots) continue;
            ctx[ph] = vm->registers.regs[r].qword();
        }
    }

    tramp(ctx);

    /* Y de vuelta, SOLO lo que el bloque escribe.  Devolver tambien lo que
     * unicamente se lee sobreescribiria el registro de la VM con lo que el
     * codigo nativo dejara ahi, que no es asunto suyo -- y eso no falla,
     * corrompe. */
    for (int i = 0; i < nops; ++i) {
        const uint16_t p = loc_de(i);
        if ((vx::asm_loc_flags(p) & vx::kAsmLocWrites) == 0) continue;
        const uint8_t r = vx::asm_loc_vm_reg(p);
        const uint8_t ph = vx::asm_loc_phys(p);
        if (vx::asm_loc_bank(p) == vx::kAsmBankWide) {
            if (ph >= vx::kAsmCtxVecSlots) continue;
            vm->registers.zmm[r].write_zmm(
                &ctx[vx::kAsmCtxGpSlots + (size_t)ph * vx::kAsmCtxVecQwords]);
        } else {
            if (ph >= vx::kAsmCtxGpSlots) continue;
            vm->registers.regs[r].qword(ctx[ph]);
        }
    }
    return 0;
}

extern "C" uint64_t vrt_asm_micro_ops(uint64_t proc, uint64_t hash,
                                      uint64_t eff, uint64_t tabla,
                                      uint64_t desc, uint64_t n) {
    auto *vm = reinterpret_cast<runtime::ProcessVM *>(proc);
    if (vm == nullptr) return 0;
    AsmTrampolineFn tramp = lookup_inline_asm_trampoline(hash);
    if (tramp == nullptr) {
        /* Sin ensamblador se emula lo que se pueda de la base -- una barrera es
         * una barrera en cualquier maquina -- pero una instruccion que CAMBIA
         * valores no se puede emular asi: los devolveria sin tocar y el
         * programa seguiria con los de antes.  Callarselo es dar por hecho un
         * trabajo que no se hizo, asi que se dice. */
        /* Una barrera SI se puede cumplir sin ensamblador -- es una barrera en
         * cualquier maquina -- asi que un bloque que solo ordena la memoria
         * sigue siendo correcto y se deja pasar. */
        if (eff & 0x8u) std::atomic_thread_fence(std::memory_order_seq_cst);
        if (n != 0) {
            /* Pero un bloque que CAMBIA valores no se puede saltar.  Antes se
             * avisaba por la salida de error y se continuaba con los valores
             * sin tocar: el programa seguia y daba resultados falsos, que es
             * peor que pararse -- nadie lee un aviso de un programa que
             * "funciona".
             *
             * Y este caso no es raro ni teorico: la VM tiene que poder correr
             * en cualquier arquitectura, asi que un `asm` escrito para otra no
             * se puede ejecutar aqui de ninguna forma.  Lo correcto entonces es
             * decirlo y parar; el programa portable elige otro camino con
             * `@Target`, que para eso esta.
             *
             * Es capturable (`try { } catch (FatalError e) { }`), asi que quien
             * quiera seguir puede decidirlo -- explicitamente, no por omision.
             */
            char msg[192];
            std::snprintf(msg, sizeof(msg),
                          "bloque de ensamblador no ejecutable en esta maquina "
                          "(%llu operandos): no hay ensamblador para su ISA, y "
                          "sus valores cambiarian el resultado",
                          (unsigned long long)n);
            runtime::throw_fatal(vm, runtime::FATAL_ILLEGAL_INSTRUCTION, msg);
        }
        return 0;
    }
    /* Descriptor: 8 bits por operando -- 5 de ranura (0..31) y 3 de ancho.  Con
     * 4 bits solo cabia la ranura, y entonces aqui no habia forma de saber si
     * el valor iba a `rax` o a `xmm0`: se metia en el banco general SIEMPRE, y
     * por eso el banco ancho no podia pasar por aqui.
     *
     * El ancho va en el descriptor y no se deduce del registro porque son cosas
     * distintas: `xmm3`, `ymm3` y `zmm3` son la MISMA ranura, y lo unico que
     * dice cuantos bytes hay que mover es el ancho. */
    /* Los descriptores llegan EN MEMORIA, uno por operando, detras de la tabla
     * de valores.  Antes venian empaquetados en `desc`, y ese entero le ponia
     * un techo de bits a algo que crece con cada ISA: no cabia el campo de
     * clase, y sin el un valor de ocho bytes en el banco ancho -- un `double`
     * en `xmm0` -- se metia en el general. */
    const int nops = (int)(n > vx::kAsmMaxOps ? vx::kAsmMaxOps : n);
    uint64_t *ctx = vm->asm_ctx;
    /* El contexto entero: dejar restos de un bloque anterior en las partes que
     * este no escribe seria darle entrada a un valor que nadie le paso. */
    std::memset(ctx, 0, sizeof(vm->asm_ctx));
    auto leer_desc = [&](int i, vx::AsmOperandDesc &d) {
        const uint64_t a = desc + (uint64_t)i * vx::kAsmDescBytes;
        d.clase = (uint16_t)vm->vm_mem.read_u16(a);
        d.ranura = (uint16_t)vm->vm_mem.read_u16(a + 2);
        d.bytes = (uint16_t)vm->vm_mem.read_u16(a + 4);
        d.flags = (uint16_t)vm->vm_mem.read_u16(a + 6);
    };
    auto en_banco_ancho = [](const vx::AsmOperandDesc &d) {
        return d.clase == vx::ASM_RC_VEC || d.clase == vx::ASM_RC_FP;
    };
    for (int i = 0; i < nops; ++i) {
        vx::AsmOperandDesc d;
        leer_desc(i, d);
        const uint64_t slot = tabla + (uint64_t)i * vx::kAsmSlotBytes;
        if (d.ranura >= vx::kAsmCtxGpSlots) continue; // fuera del contexto
        if (!en_banco_ancho(d)) {
            ctx[d.ranura] = vm->vm_mem.read_u64(slot);
            continue;
        }
        if (!vx::asm_cabe_en_ranura((unsigned)d.bytes * 8)) continue;
        uint8_t *dst = reinterpret_cast<uint8_t *>(
            &ctx[vx::kAsmCtxGpSlots + (size_t)d.ranura * vx::kAsmCtxVecQwords]);
        vm->vm_mem.read_bytes(slot, dst, d.bytes ? d.bytes : 8);
    }
    tramp(ctx);
    for (int i = 0; i < nops; ++i) {
        vx::AsmOperandDesc d;
        leer_desc(i, d);
        const uint64_t slot = tabla + (uint64_t)i * vx::kAsmSlotBytes;
        if (d.ranura >= vx::kAsmCtxGpSlots) continue;
        if (!en_banco_ancho(d)) {
            vm->vm_mem.write_u64(slot, ctx[d.ranura]);
            continue;
        }
        if (!vx::asm_cabe_en_ranura((unsigned)d.bytes * 8)) continue;
        const uint8_t *src = reinterpret_cast<const uint8_t *>(
            &ctx[vx::kAsmCtxGpSlots + (size_t)d.ranura * vx::kAsmCtxVecQwords]);
        vm->vm_mem.write_bytes(slot, src, d.bytes ? d.bytes : 8);
    }
    return 0;
}

/**
 * @brief Un bloque de ensamblador con operandos del banco ancho, por la via que
 *        no puede transportarlos.
 *
 * Esta via pasa los operandos por una lista de enteros, asi que un valor de
 * 128, 256 o 512 bits no cabe: ni entra ni sale.  El emisor lo detecta y manda
 * aqui en vez de emitir el bloque.
 *
 * Antes lo que se emitia era un `hlt` pelado, y eso en ejecucion es
 * INDISTINGUIBLE de que el programa termine bien: el proceso paraba a mitad de
 * la funcion y quien la llamo leia lo que hubiera quedado en R0.  Asi es como
 * `367_std_memory_variantes` devolvia un puntero -- y en otra de sus rutinas,
 * el propio byte de relleno -- en lugar de su resultado, sin una sola queja.
 *
 * @param proc @c ProcessVM* del proceso que ejecuta el bloque.
 * @return Nunca devuelve por la via normal: @c throw_fatal desvia.
 */
extern "C" uint64_t vrt_asm_wide_operand_unsupported(uint64_t proc) {
    auto *vm = reinterpret_cast<runtime::ProcessVM *>(proc);
    /* Por catalogo: un fallo en ejecucion tambien es un diagnostico, y se
     * cuenta en el idioma de quien lo lee. */
    const std::string detalle = vx::diag::format("VX7025", {});
    runtime::throw_fatal(vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
                         detalle.c_str());
    return 0;
}

void register_inline_asm_runner() {
    ffi::register_virtual_fn("vrt", "inline_asm_exec",
                             reinterpret_cast<void *>(&vrt_inline_asm_exec));
    ffi::register_virtual_fn(
        "vrt", "asm_wide_operand_unsupported",
        reinterpret_cast<void *>(&vrt_asm_wide_operand_unsupported));
    ffi::register_virtual_fn("vrt", "asm_micro_exec",
                             reinterpret_cast<void *>(&vrt_asm_micro_exec));
    ffi::register_virtual_fn("vrt", "asm_micro_regs",
                             reinterpret_cast<void *>(&vrt_asm_micro_regs));
    ffi::register_virtual_fn("vrt", "asm_micro_ops",
                             reinterpret_cast<void *>(&vrt_asm_micro_ops));
}

void build_and_register_inline_asm_trampolines(
    const std::vector<ir::IrFunction> &fns) {
    if (vx::g_asm_backend == nullptr) return; // sin ensamblador -> no-op
    // CodeCache de vida-proceso: los trampolines deben sobrevivir mientras
    // el programa corra.  Una sola instancia compartida por todos los
    // bloques asm (de cualquier modulo cargado).
    static CodeCache asm_cc;
    for (const auto &fn : fns) {
        for (const auto &blk : fn.blocks) {
            for (const auto &ins : blk.instrs) {
                // Cuerpo asm a registrar como trampoline nativo: INLINE_ASM lo
                // lleva en func_name; ASM_MICRO (asm opaco liftado, caso sin
                // operandos de registro) en asm_micros[imm].tmpl.  El interp
                // ejecuta ambos via el trampoline SOLO si hay ensamblador; si
                // no, no se registra y vrt_inline_asm_exec hace no-op (sigue
                // corriendo).
                const std::string *body = nullptr;
                std::string subst; // vive hasta el registro (: $N -> reg)
                if (ins.op == ir::IrOp::INLINE_ASM) {
                    // sustituir $N por el pick GREEDY del binding (el
                    // interp no tiene RA).  Mismo cuerpo que hashea ir_emitter.
                    subst = vx::asm_body_subst_greedy(ins.func_name,
                                                      fn.asm_reg_bindings);
                    body = &subst;
                } else if (ins.op == ir::IrOp::ASM_MICRO &&
                           ins.imm < fn.asm_micros.size()) {
                    const ir::AsmMicro &am = fn.asm_micros[ins.imm];
                    std::vector<int> phys_tmp;
                    if (am.operands.empty()) {
                        body = &am.tmpl; // sin operandos: verbatim
                    } else if (vx::asm_micro_subst_phys(am, subst)) {
                        body = &subst; // fisico fijo sustituido
                    } else if (vx::asm_micro_subst_greedy(am, subst,
                                                          phys_tmp)) {
                        // Operandos que son valores del programa: los registros
                        // los elige la misma funcion que usa el emisor, o el
                        // texto no coincidiria y no se encontrarian.
                        body = &subst;
                    }
                }
                if (body == nullptr) continue;
                const uint64_t hash = fnv1a64_asm(*body);
                if (lookup_inline_asm_trampoline(hash) != nullptr) continue;
                std::string err;
                AsmTrampolineFn tp = build_asm_trampoline(*body, asm_cc, &err);
                if (tp == nullptr) {
                    std::fprintf(stderr,
                                 "[asm] no se pudo ensamblar el trampoline de "
                                 "inline-asm en '%s': %s\n",
                                 fn.name.c_str(), err.c_str());
                    continue;
                }
                register_inline_asm_trampoline(hash, tp);
            }
        }
    }
}

/* ABI del trampoline: @c void tramp(uint64_t ctx[16]).  El primer argumento
 * (ctx) llega en rcx (Win64) o rdi (SysV).  Layout del prologo/epilogo
 * (documentado en el header):
 *
 *   push rbx/rbp/rsi/rdi/r12..r15      ; salvar callee-saved (los pisamos)
 *   push <ctx>                          ; [rsp] = ctx (sobrevive el asm)
 *   <load 16 GP host desde [ctx + id*8]; cargar <ctx> el ULTIMO>
 *   <USER ASM>                          ; rsp 16-alineado aqui
 *   push rax                            ; salvar rax (resultado) temporal
 *   mov rax, [rsp+8]                    ; recargar ctx (estaba en [rsp+8])
 *   <save 15 GP host (todos menos rax) a [ctx + id*8]>
 *   pop rcx ; mov [rax+0], rcx          ; salvar rax (id 0)
 *   add rsp, 8                          ; descartar el slot de ctx
 *   pop r15..rbx                        ; restaurar callee-saved
 *   ret
 *
 * Generico: el mismo prologo/epilogo sirve para CUALQUIER asm + bindings
 * (carga/salva los 16; el caller usa solo los ids que le interesan).  El
 * ctx en pila hace el trampoline reentrante y absorbe clobbers de rbx/rbp.
 */
AsmTrampolineFn build_asm_trampoline(const std::string &user_asm, CodeCache &cc,
                                     std::string *err) {
    if (vx::g_asm_backend == nullptr) {
        if (err) *err = "no hay backend de ensamblado (Keystone) registrado";
        return nullptr;
    }

#if defined(_WIN32)
    const char *CTX = "rcx"; // Win64: primer arg en rcx
#else
    const char *CTX = "rdi"; // SysV: primer arg en rdi
#endif

    std::string nasm;
    nasm.reserve(user_asm.size() + 1024);

    /* --- prologo: salvar callee-saved --- */
    nasm += "push rbx\npush rbp\npush rsi\npush rdi\n";
    nasm += "push r12\npush r13\npush r14\npush r15\n";
    /* salvar ctx en la pila (sobrevive cualquier clobber del asm) */
    nasm += "push ";
    nasm += CTX;
    nasm += "\n";

    /* --- cargar los 16 GP host desde ctx ([ctx + id*8]); rsp (id 4) NO se
     * carga (no se pisa el stack pointer).  El registro que TRAE ctx se
     * carga el ULTIMO (ya no se necesita ctx tras eso). --- */
    static const struct {
        const char *r;
        int id;
    } REGS[] = {
        {"rax", 0},  {"rcx", 1},  {"rdx", 2},  {"rbx", 3},  {"rbp", 5},
        {"rsi", 6},  {"rdi", 7},  {"r8", 8},   {"r9", 9},   {"r10", 10},
        {"r11", 11}, {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
    };
    char line[64];
    /* OJO: Keystone (NASM) interpreta los enteros BARE como HEX -> emitir
     * los offsets como 0x%x (el valor en hex) para que el disp sea correcto. */
    for (const auto &e : REGS) {
        if (std::strcmp(e.r, CTX) == 0) continue; // ctx-reg: el ultimo
        std::snprintf(line, sizeof(line), "mov %s, [%s + 0x%x]\n", e.r, CTX,
                      e.id * 8);
        nasm += line;
    }
    /* el reg que trae ctx: cargarlo ahora (su valor logico esta en ctx) */
    {
        int ctx_id = (std::strcmp(CTX, "rcx") == 0) ? 1 : 7; // rcx=1, rdi=7
        std::snprintf(line, sizeof(line), "mov %s, [%s + 0x%x]\n", CTX, CTX,
                      ctx_id * 8);
        nasm += line;
    }

    /* --- el banco ancho, si el cuerpo lo usa ---
     * El micro asm existe para las instrucciones sin representacion fiel en el
     * IR, y muchas de esas son vectoriales: sin traer y devolver estos
     * registros, esos bloques no se podian ejecutar y se quedaban sin elevar.
     * La limitacion no era del lenguaje, era de este contexto.
     *
     * Solo se toca si aparecen, para no pagar 16 movimientos en el caso
     * comun. */
    /* CUALES usa, no solo si usa alguno.  Guardar y devolver los dieciseis
     * eran treinta y dos movimientos de 16 bytes para un bloque que casi
     * siempre toca uno o dos: el resto es copiar ceros de ida y de vuelta.
     *
     * Se leen del propio cuerpo, que es lo unico que hay aqui -- el trampolin
     * se indexa por el hash del texto, asi que dos cuerpos distintos son dos
     * trampolines y no se puede compartir de mas. */
    bool usa_slot[16] = {false};
    bool usa_ancho = false;
    for (size_t p = 0; p + 3 < user_asm.size(); ++p) {
        const char c0 = (char)std::tolower((unsigned char)user_asm[p]);
        if (c0 != 'x' && c0 != 'y' && c0 != 'z') continue;
        if (std::tolower((unsigned char)user_asm[p + 1]) != 'm' ||
            std::tolower((unsigned char)user_asm[p + 2]) != 'm')
            continue;
        size_t q = p + 3;
        if (q >= user_asm.size() || !std::isdigit((unsigned char)user_asm[q]))
            continue;
        int n = 0;
        while (q < user_asm.size() && std::isdigit((unsigned char)user_asm[q]))
            n = n * 10 + (user_asm[q++] - '0');
        if (n < 0 || n >= 16) continue; // fuera del contexto: no se toca
        usa_slot[n] = true;
        usa_ancho = true;
    }
    if (usa_ancho) {
        /* El que trae el contexto esta en la pila.  DONDE empiezan los anchos
         * no se escribe aqui: sale de la misma constante que dimensiona el
         * contexto.  Estaba puesto el 128 a mano -- 16 generales por 8 -- y al
         * crecer el banco general para arm64 este codigo siguio leyendo en el
         * sitio viejo, que ya era de otro.  No da error: mueve el valor
         * equivocado. */
        const unsigned base_ancho = vx::kAsmCtxGpSlots * 8;
        nasm += "push r11\n";
        nasm += "mov r11, [rsp + 8]\n";
        /* El 128 seguia escrito a mano AQUI.  El aviso de arriba lo cuenta y la
         * DEVOLUCION ya salia de la constante, pero la carga no: se leia en 128
         * y se escribia en 256, asi que el valor que entraba al bloque no era
         * el que se habia dejado.  Y como el bloque igual escribia algo, no
         * daba error -- daba otro resultado. */
        for (int i = 0; i < 16; ++i) {
            std::snprintf(line, sizeof(line), "movups xmm%d, [r11 + 0x%x]\n", i,
                          base_ancho + i * vx::kAsmCtxVecQwords * 8);
            nasm += line;
        }
        nasm += "pop r11\n";
    }

    /* --- cuerpo del usuario --- */
    nasm += user_asm;
    if (!user_asm.empty() && user_asm.back() != '\n') nasm += "\n";

    /* --- devolver el banco ancho, antes de tocar los generales --- */
    if (usa_ancho) {
        nasm += "push r11\n";
        nasm += "mov r11, [rsp + 8]\n";
        const unsigned base_ancho = vx::kAsmCtxGpSlots * 8;
        for (int i = 0; i < 16; ++i) {
            std::snprintf(line, sizeof(line), "movups [r11 + 0x%x], xmm%d\n",
                          base_ancho + i * vx::kAsmCtxVecQwords * 8, i);
            nasm += line;
        }
        nasm += "pop r11\n";
    }

    /* --- epilogo: salvar los 16 GP host de vuelta a ctx --- */
    nasm += "push rax\n";           // salvar rax (resultado) temporal
    nasm += "mov rax, [rsp + 8]\n"; // recargar ctx (rax = ctx)
    for (const auto &e : REGS) {
        if (e.id == 0) continue; // rax se salva al final (via pop)
        std::snprintf(line, sizeof(line), "mov [rax + 0x%x], %s\n", e.id * 8,
                      e.r);
        nasm += line;
    }
    nasm += "pop rcx\n";            // rcx = rax salvado
    nasm += "mov [rax + 0], rcx\n"; // salvar rax (id 0)
    nasm += "add rsp, 8\n";         // descartar el slot de ctx
    nasm += "pop r15\npop r14\npop r13\npop r12\n";
    nasm += "pop rdi\npop rsi\npop rbp\npop rbx\n";
    nasm += "ret\n";

    /* Diagnostico opt-in: volcar el NASM generado. */
    if (util::flag_on(util::FlagId::AsmTrampDebug)) {
        std::fprintf(stderr,
                     "=== trampoline NASM ===\n%s=======================\n",
                     nasm.c_str());
    }

    /* --- ensamblar (Keystone) --- */
    vx::AsmAssembleResult ar =
        vx::g_asm_backend->assemble(nasm, vx::AsmArch::X86_64);
    if (!ar.ok || ar.bytes.empty()) {
        if (err) *err = ar.ok ? "ensamblado vacio" : ar.error;
        return nullptr;
    }
    if (util::flag_on(util::FlagId::AsmTrampDebug)) {
        std::fprintf(stderr, "=== bytes (%zu) ===\n", ar.bytes.size());
        for (size_t i = 0; i < ar.bytes.size(); ++i)
            std::fprintf(stderr, "%02x ", ar.bytes[i]);
        std::fprintf(stderr, "\n");
    }

    /* --- alojar ejecutable --- */
    uint8_t *code = cc.alloc(ar.bytes.size(), 16);
    if (!code) {
        if (err) *err = "code cache OOM";
        return nullptr;
    }
    std::memcpy(code, ar.bytes.data(), ar.bytes.size());
    cc.commit(code, ar.bytes.size());
#if defined(_WIN32)
    /* Y se dice como desenrollarlo.  Sin esto, un fallo del procesador dentro
     * del ensamblador se puede recoger o llevarse el proceso segun como haya
     * quedado la pila -- ver `registrar_desenrollado`. */
    if (!registrar_desenrollado(code, ar.bytes.size(), cc) &&
        util::flag_on(util::FlagId::AsmTrampDebug)) {
        std::fprintf(stderr, "[asm] trampoline sin info de desenrollado: un "
                             "fallo dentro del asm no sera recuperable\n");
    }
#endif
    return reinterpret_cast<AsmTrampolineFn>(code);
}

} // namespace jit
