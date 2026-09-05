/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file exec_instruction_meta.cpp
 * @brief Implementacion de las instrucciones de meta-programacion OOP:
 *        defclass, deffield, defmethod, findclass.
 *
 * @section design Modelo de POO dinamica
 *
 * VestaVM construye toda la metadata de clases (ClassInfo, FieldInfo,
 * MethodInfo) en runtime via @c ClassRegistry.  Estas instrucciones son el
 * puente entre el bytecode y el registry: leen una struct de parametros
 * desde memoria VM y delegan al registry, devolviendo el ClassInfo* /
 * resultado en el registro destino.
 *
 * @section encoding Codificacion
 *
 * Todas estas instrucciones usan FIXED_4 / REG mode con
 * @c decode_instr_two_op_reg:
 *
 *   [0x00][opcode2][byte2][byte3]
 *
 * donde byte2 = (r_dst << 4) | r_params para defclass / findclass, o
 *       byte2 = (r_class << 4) | r_params para deffield / defmethod.
 *
 * El segundo registro contiene la VM-addr a la struct de parametros
 * (DefClassParams / DefFieldParams / DefMethodParams / FindClassParams).
 * Cada struct se lee con vm_mem.read_bytes; los punteros a strings
 * (name_addr) tambien viven en memoria VM y se leen igual.
 *
 * @section perf Coste
 *
 * - defclass / findclass: ~1 lookup hash O(1) + 1 alloc en el registry.
 * - deffield / defmethod: ~1 realocacion del array + rebuild lookup
 *   (O(n) donde n es el numero de fields/methods de la clase).  Solo
 *   ocurre durante la inicializacion del modulo.
 * - Tras la inicializacion, NEWOBJ + GETFIELD + CALLVIRT son fast paths
 *   sin costes adicionales (offsets cacheados en el FieldInfo).
 */

#include "runtime/exec_instruction.h"
#include "runtime/mem_full_semantics.h"
#include "runtime/proceso_runtime.h"
#include "runtime/exception_runtime.h"
#include "runtime/native_invoke.h"
#include "loader/loader.h"
#include "loader/class_registry.h"
#include "loader/oop_types.h"
#include "ffi/native_ffi.h"
#include "gc/gc_heap.h"
#include <cstdio>
#include <cstdlib>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <cstring>
#include <string>

namespace runtime {

// -------------------------------------------------------------------------
//  Layouts de parametros en memoria VM
//
//  Estas structs son la ABI publica entre el bytecode y los exec
//  functions.  Cualquier cambio invalida los .velb existentes; mantener
//  los offsets estables.
// -------------------------------------------------------------------------

/**
 * @brief Parametros de la instruccion @c defclass.  Layout 32 bytes.
 *
 *   +0  [8]  name_addr     -- VM addr a los bytes UTF-8 del nombre
 *   +8  [4]  name_len      -- numero de bytes del nombre
 *   +12 [4]  flags         -- CLASS_FLAG_* + visibilidad (bits 0-1)
 *   +16 [8]  super_class   -- ClassInfo* (raw uint64) o 0 = sin super
 *   +24 [8]  _reserved     -- puesto a 0; reservado para extensiones
 */
struct DefClassParamsLayout {
    uint64_t name_addr;
    uint32_t name_len;
    uint32_t flags;
    uint64_t super_class;
    uint64_t _reserved;
};
static_assert(sizeof(DefClassParamsLayout) == 32, "DefClassParams ABI");

/**
 * @brief Parametros de la instruccion @c deffield.  Layout 32 bytes.
 *
 *   +0  [8] name_addr
 *   +8  [4] name_len
 *   +12 [1] kind         -- FIELD_PRIMITIVE / FIELD_CLASS / FIELD_STRUCT
 *   +13 [1] access       -- FIELD_PUBLIC / FIELD_PRIVATE / FIELD_PROTECTED
 *   +14 [1] is_static    -- 0/1
 *   +15 [1] _pad
 *   +16 [4] size_bytes   -- 1, 2, 4 u 8 (slot redondeado a 8)
 *   +20 [4] _pad2
 *   +24 [8] type_class   -- ClassInfo* (0 si primitive)
 */
struct DefFieldParamsLayout {
    uint64_t name_addr;
    uint32_t name_len;
    uint8_t kind;
    uint8_t access;
    uint8_t is_static;
    uint8_t _pad;
    uint32_t size_bytes;
    uint32_t _pad2;
    uint64_t type_class;
};
static_assert(sizeof(DefFieldParamsLayout) == 32, "DefFieldParams ABI");

/**
 * @brief Parametros de la instruccion @c defmethod.  Layout 40 bytes.
 *
 *   +0  [8]  name_addr
 *   +8  [4]  name_len
 *   +12 [4]  descriptor_len
 *   +16 [8]  descriptor_addr
 *   +24 [8]  code_vaddr   -- direccion VM del primer byte del bytecode
 *   +32 [8]  flags         -- METHOD_FLAG_*
 */
struct DefMethodParamsLayout {
    uint64_t name_addr;
    uint32_t name_len;
    uint32_t descriptor_len;
    uint64_t descriptor_addr;
    uint64_t code_vaddr;
    uint64_t flags;
};
static_assert(sizeof(DefMethodParamsLayout) == 40, "DefMethodParams ABI");

/**
 * @brief Parametros de la instruccion @c findclass.  Layout 16 bytes.
 *
 *   +0  [8] name_addr
 *   +8  [4] name_len
 *   +12 [4] _pad
 */
struct FindClassParamsLayout {
    uint64_t name_addr;
    uint32_t name_len;
    uint32_t _pad;
};
static_assert(sizeof(FindClassParamsLayout) == 16, "FindClassParams ABI");

/**
 * @brief Parametros de la instruccion @c findmethod.  Layout 24 bytes.
 *
 *   +0  [8] class_ptr   -- ClassInfo* donde buscar el metodo
 *   +8  [8] name_addr   -- VM addr de los bytes UTF-8 del nombre
 *   +16 [4] name_len    -- numero de bytes del nombre
 *   +20 [4] _pad
 *
 * El resultado es un MethodInfo* (raw uint64) o 0 si no existe.
 * Usado por la lowering AOP para resolver el target de un advice y
 * pasarlo a @c addadvice.  Coste O(1) amortizado via tabla hash de
 * la clase (factor de carga 0.5, FNV-1a + linear probing).
 */
struct FindMethodParamsLayout {
    uint64_t class_ptr;
    uint64_t name_addr;
    uint32_t name_len;
    uint32_t _pad;
};
static_assert(sizeof(FindMethodParamsLayout) == 24, "FindMethodParams ABI");

// -------------------------------------------------------------------------
//  Helper: leer una cadena de memoria VM en una std::string.
//
//  Solo se usa durante la inicializacion del modulo (1-2 veces por
//  clase/field/method), por lo que el coste de la copia es trivial
//  comparado con el overhead de definicion.
// -------------------------------------------------------------------------
static std::string read_vm_string(ProcessVM *vm, uint64_t addr, uint32_t len) {
    if (len == 0 || addr == 0) return std::string();
    std::string out;
    out.resize(len);
    vm->vm_mem.read_bytes(addr, out.data(), len);
    return out;
}

// -------------------------------------------------------------------------
//  Helper: acceso al ClassRegistry global del Loader propietario.
// -------------------------------------------------------------------------
static loader::ClassRegistry &registry_of(ProcessVM *vm) {
    return vm->scheduler.vm_reference.loader_public.class_registry();
}

// =========================================================================
//  0xC9 DEFCLASS r_dst, r_params
// =========================================================================

/**
 * @brief Crea una clase nueva (sin fields ni methods iniciales).
 *
 * Lee los parametros de memoria VM, invoca @c ClassRegistry::define_class
 * y devuelve el puntero al @c ClassInfo en r_dst.  Si ya existia una
 * clase con ese nombre, devuelve la existente sin error (idempotente).
 *
 * @param vm    Proceso virtual.
 * @param instr byte2 = (r_dst<<4) | r_params.
 */
void exec_instr_defclass(ProcessVM *vm, const DecodedInstr &instr) {
    // Convencion del assembler: el primer operando textual va a reg1
    // (nibble bajo de byte2) y el segundo a reg2 (nibble alto).  Por
    // eso `defclass r_dst, r_params` -> r_dst = reg1, r_params = reg2.
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_params = instr.data_instruction.reg_data.reg2;

    const uint64_t params_addr = vm->registers.regs[r_params].qword();
    if (params_addr == 0) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }
    DefClassParamsLayout p;
    vm->vm_mem.read_bytes(params_addr, &p, sizeof(p));

    const std::string name = read_vm_string(vm, p.name_addr, p.name_len);
    if (name.empty()) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }
    auto *super = reinterpret_cast<loader::ClassInfo *>(p.super_class);
    loader::ClassInfo *cls = registry_of(vm).define_class(
        name, super, {}, {}, {}, p.flags ? p.flags : loader::CLASS_VIS_PUBLIC);
    vm->registers.regs[r_dst].qword(reinterpret_cast<uint64_t>(cls));
}

// =========================================================================
//  0xCA DEFFIELD r_class, r_params
// =========================================================================

/**
 * @brief Anade un campo a una clase ya creada con @c defclass.
 *
 * El registro resultante es 1 si la operacion tuvo exito, 0 en caso
 * contrario (clase nula, params nulos o nombre duplicado).
 */
void exec_instr_deffield(ProcessVM *vm, const DecodedInstr &instr) {
    // Misma convencion que defclass: primer operando textual va a reg1.
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_params = instr.data_instruction.reg_data.reg2;

    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_dst].qword());
    const uint64_t params_addr = vm->registers.regs[r_params].qword();
    if (cls == nullptr || params_addr == 0) {
        vm->registers.regs[R00].qword(0);
        return;
    }
    DefFieldParamsLayout p;
    vm->vm_mem.read_bytes(params_addr, &p, sizeof(p));

    loader::FieldDecl decl;
    decl.name = read_vm_string(vm, p.name_addr, p.name_len);
    decl.kind = static_cast<loader::FieldKind>(p.kind);
    decl.access = static_cast<loader::FieldAccess>(p.access);
    decl.is_static = (p.is_static != 0);
    decl.size_bytes = p.size_bytes ? p.size_bytes : 8u;
    decl.type_class = reinterpret_cast<loader::ClassInfo *>(p.type_class);

    const bool ok = registry_of(vm).add_field(cls, decl);
    vm->registers.regs[R00].qword(ok ? 1ULL : 0ULL);
}

// =========================================================================
//  0xCB DEFMETHOD r_class, r_params
// =========================================================================

/**
 * @brief Anade un metodo a una clase ya creada con @c defclass.
 *
 * El @c code_vaddr de los parametros debe apuntar al primer byte del
 * bytecode del metodo (tipicamente un label resuelto por el linker).
 * El registro resultante (R0) recibe el indice del metodo en la
 * vtable, o UINT32_MAX si fallo (clase nula, duplicado, etc.).
 */
void exec_instr_defmethod(ProcessVM *vm, const DecodedInstr &instr) {
    // Misma convencion que defclass: primer operando textual va a reg1.
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_params = instr.data_instruction.reg_data.reg2;

    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_dst].qword());
    const uint64_t params_addr = vm->registers.regs[r_params].qword();
    if (cls == nullptr || params_addr == 0) {
        vm->registers.regs[R00].qword(UINT32_MAX);
        return;
    }
    DefMethodParamsLayout p;
    vm->vm_mem.read_bytes(params_addr, &p, sizeof(p));

    loader::MethodDecl decl;
    decl.name = read_vm_string(vm, p.name_addr, p.name_len);
    decl.descriptor = read_vm_string(vm, p.descriptor_addr, p.descriptor_len);
    decl.flags = p.flags;
    decl.code_vaddr = p.code_vaddr;
    decl.code_size = 0; // el ejecutor no necesita el tamano para CALLVIRT

    const bool ok = registry_of(vm).add_method(cls, decl);
    if (!ok) {
        vm->registers.regs[R00].qword(UINT32_MAX);
        return;
    }
    // El metodo recien anadido es el ultimo del array.
    vm->registers.regs[R00].qword(static_cast<uint64_t>(cls->method_count - 1));
}

// =========================================================================
//  0xCC FINDCLASS r_dst, r_params
// =========================================================================

/**
 * @brief Busca una clase por nombre en el registry global.
 *
 * Devuelve el puntero al ClassInfo en r_dst, o 0 si no existe.
 */
void exec_instr_findclass(ProcessVM *vm, const DecodedInstr &instr) {
    // Misma convencion que defclass: primer operando textual va a reg1.
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_params = instr.data_instruction.reg_data.reg2;

    const uint64_t params_addr = vm->registers.regs[r_params].qword();
    if (params_addr == 0) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }
    FindClassParamsLayout p;
    vm->vm_mem.read_bytes(params_addr, &p, sizeof(p));

    const std::string name = read_vm_string(vm, p.name_addr, p.name_len);
    loader::ClassInfo *cls = registry_of(vm).find_class(name);
    vm->registers.regs[r_dst].qword(reinterpret_cast<uint64_t>(cls));
}

// =========================================================================
//  0xCD FINDMETHOD r_dst, r_params
// =========================================================================

/**
 * @brief Busca un metodo por nombre dentro de una clase (lookup hash O(1)).
 *
 * El resultado en r_dst es @c MethodInfo* (raw uint64), o 0 si no
 * existe.  Pensado para ser la primera mitad del par
 * (findmethod -> addadvice) que usa la lowering AOP en __module_init.
 */
void exec_instr_findmethod(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_params = instr.data_instruction.reg_data.reg2;

    const uint64_t params_addr = vm->registers.regs[r_params].qword();
    if (params_addr == 0) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }
    FindMethodParamsLayout p;
    vm->vm_mem.read_bytes(params_addr, &p, sizeof(p));

    auto *cls = reinterpret_cast<loader::ClassInfo *>(p.class_ptr);
    if (cls == nullptr) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }
    const std::string name = read_vm_string(vm, p.name_addr, p.name_len);
    loader::MethodInfo *m = loader::ClassRegistry::find_method(cls, name);
    vm->registers.regs[r_dst].qword(reinterpret_cast<uint64_t>(m));
}

// =========================================================================
//  0xCF FINDFIELD r_dst, r_params
// =========================================================================

/**
 * @brief Busca un campo por nombre dentro de una clase (lookup hash O(1)).
 *
 * Comparte el mismo layout de params que @c findmethod
 * (@c FindMethodParamsLayout: class_ptr + name_addr + name_len).  El
 * resultado en r_dst es @c FieldInfo* (raw uint64), o 0 si no existe.
 * Util para reflexion: combinar con un lector de offset (futura
 * instruccion freadi/fwritei) para acceso dinamico a fields por nombre.
 */
void exec_instr_findfield(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_params = instr.data_instruction.reg_data.reg2;

    const uint64_t params_addr = vm->registers.regs[r_params].qword();
    if (params_addr == 0) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }
    FindMethodParamsLayout p; // mismo shape: class_ptr + name_addr + name_len
    vm->vm_mem.read_bytes(params_addr, &p, sizeof(p));

    auto *cls = reinterpret_cast<loader::ClassInfo *>(p.class_ptr);
    if (cls == nullptr) {
        vm->registers.regs[r_dst].qword(0);
        return;
    }
    const std::string name = read_vm_string(vm, p.name_addr, p.name_len);
    loader::FieldInfo *f = loader::ClassRegistry::find_field(cls, name);
    vm->registers.regs[r_dst].qword(reinterpret_cast<uint64_t>(f));
}

// =========================================================================
//  0xCE ADDADVICE r_target, r_advice
//
//  Codificacion FIXED_4 con convention B (raw bytes):
//    [0x00][0xCE][byte2][byte3]
//  byte2 = (r_advice << 4) | r_target  (decodificado en reg1=lo, reg2=hi
//          siguiendo la convencion de los meta opcodes)
//  byte3 = kind (ADVICE_BEFORE=0, ADVICE_AFTER=1, ADVICE_AROUND=2)
//
//  R0 = 1 si se registro el advice; 0 si fallo (puntero null o firma
//  incompatible entre target y advice).
// =========================================================================

void exec_instr_addadvice(ProcessVM *vm, const DecodedInstr &instr) {
    // addadvice usa decode_instr_raw_bytes (Convention B).  En esa
    // convencion reg1 = byte2 raw, reg2 = byte3 raw.  Nuestro
    // empaquetado: byte2 = (r_advice<<4) | r_target, byte3 = kind.
    const uint8_t b2 = instr.data_instruction.reg_data.reg1;
    const uint8_t kind = instr.data_instruction.reg_data.reg2;
    const uint8_t r_target = b2 & 0x0F;
    const uint8_t r_advice = (b2 >> 4) & 0x0F;

    auto *target = reinterpret_cast<loader::MethodInfo *>(
        vm->registers.regs[r_target].qword());
    auto *advice = reinterpret_cast<loader::MethodInfo *>(
        vm->registers.regs[r_advice].qword());
    if (target == nullptr || advice == nullptr) {
        vm->registers.regs[R00].qword(0);
        return;
    }
    const bool ok = registry_of(vm).add_advice(target, kind, advice);
    vm->registers.regs[R00].qword(ok ? 1ULL : 0ULL);
}

// -------------------------------------------------------------------------
// GETSTATIC / SETSTATIC - acceso directo a campos estaticos de una clase
//
// Layout fisico (FIXED_8): [0x00][0x60|0x61][regs][_pad][offset_u32_LE]
// Convencion de operandos (data_instruction.static_data):
//   getstatic: r0=r_dst,   r1=r_class
//   setstatic: r0=r_class, r1=r_value
//
// El opcode lee/escribe SIEMPRE 8 bytes (i64) en cls->static_data + offset.
// El frontend Vesta hace truncate post-load para tipos mas pequenos (i8/i16/
// i32) usando shl+sar igual que en LOAD generico.  Esto mantiene los dos
// opcodes minimos (no necesitan size_code) sin perder funcionalidad.
// -------------------------------------------------------------------------

/**
 * @brief Lee 8 bytes desde el static_data de una ClassInfo a un registro.
 *
 * @c reg[r_dst] = *(uint64_t*)(cls->static_data + offset).  Si @c cls es
 * nullptr o @c cls->static_data es nullptr, lanza FATAL_NULL_POINTER
 * capturable via try/catch FatalError.
 */
void exec_instr_getstatic(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.static_data.r0;
    const uint8_t r_class = instr.data_instruction.static_data.r1;
    const uint32_t offset = instr.data_instruction.static_data.offset;

    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_class].qword());
    if (cls == nullptr || cls->static_data == nullptr) {
        throw_fatal(vm, FATAL_NULL_POINTER,
                    "getstatic: ClassInfo nulo o sin static_data");
        return;
    }
    // Lectura de 8 bytes desde memoria HOST (cls->static_data es uint8_t*
    // del proceso host, NO de vm_mem).  Acceso unaligned safe via memcpy.
    uint64_t val = 0;
    std::memcpy(&val, cls->static_data + offset, sizeof(uint64_t));
    vm->registers.regs[r_dst].qword(val);
}

/**
 * @brief Escribe 8 bytes a static_data de una ClassInfo desde un registro.
 *
 * @c *(uint64_t*)(cls->static_data + offset) = reg[r_value].  Mismo
 * manejo de errores que getstatic.
 */
void exec_instr_setstatic(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_class = instr.data_instruction.static_data.r0;
    const uint8_t r_value = instr.data_instruction.static_data.r1;
    const uint32_t offset = instr.data_instruction.static_data.offset;

    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_class].qword());
    if (cls == nullptr || cls->static_data == nullptr) {
        throw_fatal(vm, FATAL_NULL_POINTER,
                    "setstatic: ClassInfo nulo o sin static_data");
        return;
    }
    const uint64_t val = vm->registers.regs[r_value].qword();
    std::memcpy(cls->static_data + offset, &val, sizeof(uint64_t));
}

// ==========================================================================
// mld / mst : load/store UNIVERSAL del interprete (1 despacho).
//   addr = base +/- (index << scale) +/- disp
//   base in {r0-r15, rbp(16), rsp(17)}; index*scale (x1..64); disp int16;
//   ancho 1/2/4/8 (GP) o 16/32/64 (vector, banco FP -- pendiente); host/vm.
// Resuelve la codificacion que faltaba (rbp/rsp como base, que el SIB no
// admite) -> el spill pasa de 3 instrucciones a 1.  Banco GP en v1 (el spill
// del interp es siempre GP de 8B: el regalloc es GP-only y los floats se
// derraman como su patron de bits i64).  El banco FP se anade despues.
// ==========================================================================

/* `mem_full_addr` y la carga en si viven en `runtime/mem_full_semantics.h`: los
 * comparte con la instruccion FUSIONADA que carga y opera en un paso.  Tenerlo
 * escrito dos veces se separaria en cuanto alguien tocara un ancho o el signo,
 * y entonces el mismo programa daria un valor suelto y otro dentro de un
 * paquete. */

void exec_instr_mld(ProcessVM *vm, const DecodedInstr &instr) {
    const auto &m = instr.data_instruction.mem_full;
    const uint64_t addr =
        mem_full_addr(vm, m.base, m.disp, m.flags, m.index, m.scale);

    /* Banco FP: el valor cargado va DIRECTO al banco ZMM como float, sin pasar
     * por GP ni bitcast.  Los bits leidos SON la representacion IEEE; se
     * reinterpretan, no se convierten.  Va aparte porque no produce un "valor
     * cargado" en el sentido de `mem_full_load`: es otra operacion. */
    if (m.flags & kMemFpBank) {
        uint64_t raw = 0;
        if (m.flags & kMemHost)
            std::memcpy(&raw, reinterpret_cast<const void *>(addr),
                        m.width <= 8 ? m.width : 8);
        else if (m.width == 4)
            raw = vm->vm_mem.read_u32(addr);
        else
            raw = vm->vm_mem.read_u64_fast(addr);
        ZmmRegister &z = vm->registers.zmm[m.reg];
        if (m.width == 4) {
            float f;
            std::memcpy(&f, &raw, 4);
            z.write_f32(f);
        } else {
            double d;
            std::memcpy(&d, &raw, 8);
            z.write_f64(d);
        }
        return;
    }

    vm->registers.regs[m.reg].qword(mem_full_load(vm, m, addr));
}

void exec_instr_mst(ProcessVM *vm, const DecodedInstr &instr) {
    const auto &m = instr.data_instruction.mem_full;
    const uint64_t addr =
        mem_full_addr(vm, m.base, m.disp, m.flags, m.index, m.scale);
    // Banco FP (bit 4): el valor a escribir se lee DIRECTO del banco ZMM como
    // float, sin bitcast a GP.  Se reinterpretan los bits IEEE (no se
    // convierte).
    uint64_t val;
    if (m.flags & 0x10) {
        const ZmmRegister &z = vm->registers.zmm[m.reg];
        if (m.width == 4) {
            const float f = z.read_f32();
            uint32_t u;
            std::memcpy(&u, &f, 4);
            val = u;
        } else {
            const double d = z.read_f64();
            std::memcpy(&val, &d, 8);
        }
    } else {
        val = vm->registers.regs[m.reg].qword();
    }
    /* La escritura en si vive en `mem_full_semantics.h`: la comparte con las
     * fusionadas que hacen varios accesos de una vez. */
    mem_full_store(vm, m, addr, val);
}

// -------------------------------------------------------------------------
// FFI runtime dinamico: dlopen (0x62), dlsym (0x63), callni (0x64).
//
// Los tres opcodes complementan al @c calln estatico (declarado en el
// .velb por el linker via tabla de imports).  Permiten al usuario Vesta
// decidir EN RUNTIME que DLL cargar y que funcion llamar, igual que VSH
// expone @c ffi_open / @c ffi_sym / @c ffi_call.  Usan el mismo backend
// (LoadLibraryA / GetProcAddress en Win, dlopen / dlsym en POSIX) y la
// misma calling convention que CALLN (args en R01..R12, retorno en R00).
//
// Encoding fisico FIXED_4 (mismo patron que findclass / msgsend):
//   dlopen  r_dst, r_path_addr, r_path_len
//     [0x00][0x62][b2][b3]   b2=(r_dst<<4)|r_path_addr,  b3=(r_path_len<<4)
//   dlsym   r_dst, r_handle, r_name_addr, r_name_len
//     [0x00][0x63][b2][b3]   b2=(r_dst<<4)|r_handle,
//     b3=(r_name_addr<<4)|r_name_len
//   callni  r_fn
//     [0x00][0x64][b2][b3]   b2=(r_fn<<4),               b3=0
// -------------------------------------------------------------------------

/**
 * @brief Helper: lee N bytes desde @c vm_mem y los devuelve como std::string.
 *
 * Pequeno cap defensivo a 4 KB para evitar que un length corrupto cause
 * una alocacion enorme.  Los nombres de DLL y simbolos rara vez exceden
 * 256 caracteres en la practica.
 */
static std::string read_vm_string(ProcessVM *vm, uint64_t addr, uint64_t len) {
    if (len > 4096) len = 4096;
    std::string s;
    s.resize(static_cast<size_t>(len));
    if (len > 0)
        vm->vm_mem.read_bytes(addr, reinterpret_cast<uint8_t *>(&s[0]), len);
    return s;
}

void exec_instr_dlopen(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.mem_data.reg_base;
    const uint8_t r_path_addr = instr.data_instruction.mem_data.reg_index;
    const uint8_t r_path_len = instr.data_instruction.mem_data.reg_final;

    const uint64_t path_addr = vm->registers.regs[r_path_addr].qword();
    const uint64_t path_len = vm->registers.regs[r_path_len].qword();
    const std::string path = read_vm_string(vm, path_addr, path_len);

    // Carga directa via API del SO.  El SO mismo cachea handles
    // (LoadLibraryA incrementa el refcount si la DLL ya esta cargada)
    // asi que no necesitamos cache propio.  Si fallo, el handle queda
    // nullptr y reportamos error capturable.
    void *handle = nullptr;
#ifdef _WIN32
    handle = static_cast<void *>(LoadLibraryA(path.c_str()));
#else
    handle = dlopen(path.c_str(), RTLD_LAZY);
#endif
    if (handle == nullptr) {
        throw_fatalf(vm, FATAL_NULL_POINTER,
                     "dlopen: no se pudo cargar la libreria '%s'",
                     path.c_str());
        return;
    }
    vm->registers.regs[r_dst].qword(reinterpret_cast<uint64_t>(handle));
}

void exec_instr_dlsym(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.mem_data.reg_base;
    const uint8_t r_handle = instr.data_instruction.mem_data.reg_index;
    const uint8_t r_name_addr = instr.data_instruction.mem_data.reg_final;
    const uint8_t r_name_len = instr.data_instruction.mem_data.scale;

    void *handle =
        reinterpret_cast<void *>(vm->registers.regs[r_handle].qword());
    const uint64_t name_addr = vm->registers.regs[r_name_addr].qword();
    const uint64_t name_len = vm->registers.regs[r_name_len].qword();
    const std::string name = read_vm_string(vm, name_addr, name_len);

    if (handle == nullptr) {
        throw_fatal(vm, FATAL_NULL_POINTER, "dlsym: handle de libreria nulo");
        return;
    }
    void *sym = nullptr;
#ifdef _WIN32
    sym = reinterpret_cast<void *>(
        GetProcAddress(static_cast<HMODULE>(handle), name.c_str()));
#else
    sym = dlsym(handle, name.c_str());
#endif
    if (sym == nullptr) {
        throw_fatalf(vm, FATAL_NULL_POINTER,
                     "dlsym: simbolo no encontrado: '%s'", name.c_str());
        return;
    }
    vm->registers.regs[r_dst].qword(reinterpret_cast<uint64_t>(sym));
}

void exec_instr_callni(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_fn = instr.data_instruction.reg_data.reg1;
    void *fn = reinterpret_cast<void *>(vm->registers.regs[r_fn].qword());
    if (fn == nullptr) {
        throw_fatal(vm, FATAL_NULL_POINTER,
                    "callni: puntero a funcion nativa nulo");
        return;
    }
    const uint64_t argc = vm->registers.regs[R15].qword();
    if (argc > 12) {
        throw_fatalf(vm, FATAL_ILLEGAL_INSTRUCTION,
                     "callni: argc=%llu excede el maximo de 12 args",
                     static_cast<unsigned long long>(argc));
        return;
    }
    const uint64_t r = invoke_native_unchecked(fn, argc, vm);
    vm->registers.regs[R00].qword(r);
}

/**
 * @brief Aloca bloque GC + deposita host_ptr al payload en r_dst.
 *
 * Fusion atomic del trio (gcalloc + gcderef + xchg).  Misma logica que
 * @c gc_heap.alloc seguido de @c gc_heap.deref, pero en una sola
 * instruccion VM (3x speedup vs la secuencia de 3 instr separadas).
 *
 * Tamano maximo defensivo: rechazamos size > 256 MB (casi siempre bug
 * del frontend con underflow unsigned).
 */
void exec_instr_gcallocp(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_size = instr.data_instruction.reg_data.reg2;
    const uint64_t size_u = vm->registers.regs[r_size].qword();

    constexpr uint64_t MAX_GCALLOC_SIZE = 256ULL * 1024ULL * 1024ULL;
    if (size_u > MAX_GCALLOC_SIZE) {
        throw_fatalf(vm, FATAL_OUT_OF_MEMORY,
                     "gcallocp: tamano excesivo (%llu bytes > %llu MB)",
                     static_cast<unsigned long long>(size_u),
                     static_cast<unsigned long long>(MAX_GCALLOC_SIZE /
                                                     (1024ULL * 1024ULL)));
        return;
    }

    // Aloca via gc_heap.  Si OOM, devuelve GC_NULL_HANDLE.  El emisor IR
    // ya envuelve esta instruccion con save/restore de live regs porque
    // gc_heap.alloc puede disparar minor/major GC (evacuacion).
    const size_t size_bytes = static_cast<size_t>(size_u);
    gc::GcHandle h = vm->gc_heap.alloc(size_bytes);
    if (h == gc::GC_NULL_HANDLE) {
        throw_fatalf(vm, FATAL_OUT_OF_MEMORY,
                     "gcallocp: GcHeap sin memoria para %llu bytes",
                     static_cast<unsigned long long>(size_u));
        return;
    }

    // Resolver el handle a host_ptr (payload start, post-GcHeader).
    // gc_heap.alloc ya zero-inicializa el payload, asi que los slots
    // empiezan en 0 -- importante para el stack scan conservativo:
    // un qword == 0 se descarta y nunca se confunde con handle valido
    // (h=0 esta reservado como sentinela inalcanzable en HandleTable).
    uint8_t *payload = vm->gc_heap.deref(h);
    // El bytecode referencia este box UNICAMENTE por su host_ptr (add ptr,off /
    // load / store); jamas por su GcHandle numerico.  Marcarlo host_ptr_only
    // hace que el scan conservador NO lo mantenga vivo por coincidencia
    // numerica valor==handle (falso positivo constante-vs-handle-pequeno que
    // impedia la colecta determinista de un box escapado inalcanzable).  El
    // box SI se marca por host_ptr real cuando esta vivo en algun slot.
    vm->gc_heap.mark_host_ptr_only(payload);
    vm->registers.regs[r_dst].qword(reinterpret_cast<uint64_t>(payload));
    // Los finalizadores stageados por un GC de este alloc se drenan en el safe
    // point del scheduler (tras avanzar el PC), no aqui: reentrar al interprete
    // dentro del handler corromperia la instruccion decodificada en curso.
}

} // namespace runtime
