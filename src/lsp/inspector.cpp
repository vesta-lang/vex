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
 * @file inspector.cpp
 * @brief Implementacion del inspector del ecosistema Vesta (peticiones
 *        @c vesta/* del LSP).
 *
 * Cada metodo es BAJO DEMANDA: se sirve cuando el editor lo pide, no en
 * cada pulsacion.  Las vistas baratas reutilizan el @c CompileResult
 * cacheado por @c AnalysisEngine; las caras (ir-pre, diagramas) recompilan
 * con flags concretos y cachean el resultado en @c view_cache_.  El codigo
 * nativo del JIT y del AOT se desensambla con Capstone (x86-64).
 *
 * Robustez: ningun metodo propaga excepciones; ante un fallo controlado
 * devuelve un objeto con @c error / @c unsupported / @c incompatible.  El
 * caller (lsp_server) ademas envuelve todo en try/catch como red final.
 */

#include "lsp/inspector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <utility>
#include <vector>

#include <capstone/capstone.h>

#include <filesystem>

#include "analysis/asa/dump.h"      // la vista del conocimiento
#include "analysis/asa/producers.h" // produce()
#include "analyze/asm_report.h"     // registrar_productor_asm()
#include "aot/aot_analyze.h"
#include "analyze/bigo.h"
#include "lsp/symbol_index.h"            // uri_to_fs_path
#include "jit/vreg_select.h"             // vreg_ultimo_motivo
#include "vx/asm/instr_db.h"             // microarquitecturas y CPU conocidas
#include "vx/asm/asm_effects.h"          // isa_of_arch(): arquitectura -> ISA
#include "vx/asm/asm_cfg.h"              // el flujo de un bloque escrito a mano
#include "vx/module/namespace_flatten.h" // demangle_symbol: el nombre escrito
#include "toolchain/native_backend.h"    // el mismo codegen que usa el AOT real
#include "ir/ssa_ir.h"
#include "ir/ssa_ir_serialize.h"
#include "jit/code_cache.h"
#include "jit/runtime_entries.h"
#include "jit/vreg_pipeline.h"
#include "lsp/document_store.h"
#include "vx/compiler.h"
#include "vx/parser.h" // set/get_aot_condcomp_target (vistas por OS/arch)

namespace lsp {

namespace {

/// Normaliza el arch del inspector al que espera el parser/codegen.  Una sola
/// conversion, compartida con el analisis (@ref lsp::norm_target_arch).
inline std::string norm_arch(const std::string &a) {
    return norm_target_arch(a);
}

/// RAII: aplica el override de @Target(os:...) del inspector.  La guarda es la
/// misma que usa el analisis: dos formas de fijar el mismo objetivo acabarian
/// discrepando, y entonces la vista y los diagnosticos hablarian de maquinas
/// distintas sin decirlo.
struct InspectTargetGuard {
    CondCompTargetGuard guard;
    explicit InspectTargetGuard(const InspectTarget &t)
        : guard(t.active() ? t.os : std::string(),
                t.active() ? t.arch : std::string()) {}
};

/**
 * @brief Las opciones con las que compilar una vista para @p target.
 *
 * Existe para que el nivel de optimizacion se aplique en UN sitio.  Estaba
 * escrito cinco veces -- una por vista -- y ninguna lo miraba: se pedia el IR a
 * @c -O0 y a @c -O3 y salia el mismo texto, porque las cinco construian sus
 * opciones a mano y ninguna leia el campo.
 *
 * @param target Lo que la vista pidio.
 * @return Opciones listas para @c compile_vx_source / @c compile_vx_project.
 */
static vx::CompileOptions view_options(const InspectTarget &target) {
    vx::CompileOptions o;
    o.module_name = "main";
    // -1 = el nivel del analisis normal, que es lo que se quiere por defecto.
    if (target.opt >= 0) o.opt_level = target.opt;
    return o;
}

/**
 * @brief Compila el documento como lo haria el compilador de verdad.
 *
 * SIEMPRE como proyecto cuando el fichero esta en disco.  Compilar el fichero
 * suelto solo funciona si no importa nada, y decidirlo mirando el fuente es un
 * criterio mas que puede discrepar: cuando falla, los imports no resuelven y no
 * sale IR -- ni disposicion de tipos, ni coste, ni ninguna de las vistas --,
 * por un motivo que no tiene que ver con el programa sino con como se le
 * pregunto.  La unica excepcion es fisica: un buffer que aun no esta en disco
 * no tiene raiz desde la que resolver nada.
 *
 * El texto vivo del editor manda sobre el del disco: se pasa como overlay para
 * que las vistas hablen de lo que se esta escribiendo, no de lo ultimo
 * guardado.
 *
 * @param uri  Documento.
 * @param text Su texto actual.
 * @param co   Opciones ya preparadas (@ref view_options y lo que anada quien
 *             llame).
 * @return El resultado de compilar.
 */
static vx::CompileResult compile_document(const std::string &uri,
                                          const std::string &text,
                                          const vx::CompileOptions &co) {
    const std::string fs_path = uri_to_fs_path(uri);
    if (fs_path.empty() || !std::ifstream(fs_path).good())
        return vx::compile_vx_source(text, uri, co);
    std::unordered_map<std::string, std::string> overlay;
    overlay[fs_path] = text;
    const std::vector<std::string> raices = import_search_roots(fs_path);
    return vx::compile_vx_project(fs_path, co, &overlay, &raices);
}

/// @return true si el target pide ABI SysV (Linux/macOS); false Win64.
inline bool target_is_sysv(const InspectTarget &t) {
    if (t.os == "linux" || t.os == "macos") return true;
    if (t.os == "windows") return false;
#if defined(_WIN32)
    return false;
#else
    return true;
#endif
}

/// @return true si el target pide codegen x86-32.
inline bool target_is_mode32(const InspectTarget &t) {
    return norm_arch(t.arch) == "x86";
}

/**
 * @brief Devuelve la primera linea fuente conocida de una funcion IR.
 *
 * El IR no guarda una SourceLoc por funcion; recorre sus instrucciones
 * buscando el primer @c source_line distinto de cero.  Best-effort para
 * ubicar funciones en la lista de @c vesta/functions.
 *
 * @param fn Funcion IR.
 * @return Linea 1-based, o 0 si ninguna instruccion lleva linea.
 */
uint32_t first_source_line(const ir::IrFunction &fn) {
    for (const auto &blk : fn.blocks) {
        for (const auto &ins : blk.instrs) {
            if (ins.source_line != 0) return ins.source_line;
        }
    }
    return 0;
}

/**
 * @brief Deserializa el modulo IR (post-opt) cacheado del CompileResult.
 *
 * @param result CompileResult con @c ir_module_cache_bytes.
 * @param out    Modulo IR destino.
 * @return true si la deserializacion fue exitosa y el modulo tiene
 *         funciones; false en otro caso.
 */
bool parse_post_opt_module(const vx::CompileResult &result, ir::IrModule &out) {
    if (result.ir_module_cache_bytes.empty()) return false;
    return ir::parse_ir_module_cache(result.ir_module_cache_bytes, out);
}

/**
 * @brief Selecciona la funcion objetivo de las vistas JIT/AOT.
 *
 * Si @p wanted no esta vacio, busca esa funcion exacta.  Si esta vacio,
 * prefiere @c "main"; si no hay, devuelve la primera funcion no nativa y
 * no macro-compilada del modulo.
 *
 * @param mod    Modulo IR.
 * @param wanted Nombre pedido (vacio = auto).
 * @return Puntero a la funcion, o nullptr si no hay candidata.
 */
const ir::IrFunction *pick_function(const ir::IrModule &mod,
                                    const std::string &wanted) {
    if (!wanted.empty()) {
        for (const auto &fn : mod.functions) {
            if (fn.name == wanted) return &fn;
        }
        // Funciones comptime: el frontend las baja como @c __macro_<nombre>.
        // Si el hover pidio @c M_foo, probar @c __macro_M_foo.
        const std::string macro = "__macro_" + wanted;
        for (const auto &fn : mod.functions) {
            if (fn.name == macro) return &fn;
        }
        return nullptr;
    }
    // Auto: preferir main (nombre exacto o sufijo "main").
    const ir::IrFunction *first_user = nullptr;
    for (const auto &fn : mod.functions) {
        if (fn.is_native || fn.is_macro_compiled) continue;
        if (!first_user) first_user = &fn;
        if (fn.name == "main") return &fn;
    }
    return first_user;
}

/**
 * @brief Desensambla un buffer de bytes x86-64 a texto legible via Capstone.
 *
 * Una linea por instruccion con offset relativo, mnemonico y operandos.  Si
 * Capstone no puede abrir o decodificar, devuelve un mensaje informativo en
 * lugar de fallar.
 *
 * @param code      Bytes del codigo nativo.
 * @param code_size Numero de bytes.
 * @param base      Direccion base mostrada (offset relativo si 0).
 * @return Texto del desensamblado (multilinea).
 */
/**
 * @brief Arquitectura que el usuario pide ver.
 *
 * Las vistas de codigo maquina no son de x86: el compilador genera para varias
 * arquitecturas y ensenar solo una obligaria a compilar por fuera para mirar
 * las demas, que es justo lo que estas vistas evitan.
 *
 * @param arch Nombre pedido; vacio = la de por defecto.
 * @return La arquitectura del generador.
 */
/**
 * @brief Traduce el nombre del juego de instrucciones de coma flotante.
 * @param nombre "sse2"|"avx"|"avx512"|"x87"|"auto"; vacio o desconocido = el de
 *               por defecto.
 * @return El valor que entiende el generador.
 */
jit::FloatIsa float_isa_from_str(const std::string &nombre) {
    if (nombre == "x87") return jit::FloatIsa::X87;
    if (nombre == "avx") return jit::FloatIsa::AVX;
    if (nombre == "avx512") return jit::FloatIsa::AVX512F;
    if (nombre == "auto") return jit::FloatIsa::AUTO;
    return jit::FloatIsa::SSE2;
}

aot::AotArch arch_from_name(const std::string &arch) {
    if (arch == "x86-32" || arch == "x86_32" || arch == "i386")
        return aot::AotArch::X86_32;
    if (arch == "aarch64" || arch == "arm64") return aot::AotArch::ARM64;
    if (arch == "arm32" || arch == "armv7") return aot::AotArch::ARM32;
    if (arch == "riscv64") return aot::AotArch::RISCV64;
    return aot::AotArch::X86_64;
}

/**
 * @brief Traduce la arquitectura a lo que entiende el desensamblador.
 * @param arch     Arquitectura.
 * @param out_arch Salida: familia para Capstone.
 * @param out_mode Salida: modo para Capstone.
 * @return false si no hay desensamblador para ella.
 */
bool capstone_for(aot::AotArch arch, cs_arch &out_arch, cs_mode &out_mode) {
    switch (arch) {
    case aot::AotArch::X86_64:
        out_arch = CS_ARCH_X86;
        out_mode = CS_MODE_64;
        return true;
    case aot::AotArch::X86_32:
        out_arch = CS_ARCH_X86;
        out_mode = CS_MODE_32;
        return true;
    case aot::AotArch::X86_16:
        out_arch = CS_ARCH_X86;
        out_mode = CS_MODE_16;
        return true;
    case aot::AotArch::ARM64:
        out_arch = CS_ARCH_ARM64;
        out_mode = CS_MODE_ARM;
        return true;
    case aot::AotArch::ARM32:
        out_arch = CS_ARCH_ARM;
        out_mode = CS_MODE_ARM;
        return true;
    default: return false;
    }
}

/**
 * @brief Desensambla codigo de cualquiera de las arquitecturas que se generan.
 * @param code      Bytes.
 * @param code_size Cuantos.
 * @param base      Direccion base con la que numerar.
 * @param arch      Arquitectura de esos bytes.
 * @return El desensamblado, una instruccion por linea.
 */
std::string disasm_native(const uint8_t *code, size_t code_size, uint64_t base,
                          aot::AotArch arch) {
    if (!code || code_size == 0) return "(codigo vacio)";
    cs_arch cs_a = CS_ARCH_X86;
    cs_mode cs_m = CS_MODE_64;
    if (!capstone_for(arch, cs_a, cs_m))
        return "(no hay desensamblador para esta arquitectura)";
    csh handle;
    if (cs_open(cs_a, cs_m, &handle) != CS_ERR_OK)
        return "(Capstone: no se pudo abrir el desensamblador)";
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_insn *insn = nullptr;
    const size_t count = cs_disasm(handle, code, code_size, base, 0, &insn);
    std::ostringstream oss;
    if (count > 0) {
        for (size_t i = 0; i < count; ++i) {
            const uint64_t off = insn[i].address - base;
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%04llx",
                          static_cast<unsigned long long>(off));
            oss << buf << "  " << insn[i].mnemonic;
            if (insn[i].op_str[0] != '\0') oss << ' ' << insn[i].op_str;
            oss << '\n';
        }
        cs_free(insn, count);
    } else {
        oss << "(Capstone no pudo desensamblar los bytes generados)\n";
    }
    cs_close(&handle);
    return oss.str();
}

/**
 * @brief Desensambla correlando cada instruccion con su linea, sin anotar.
 *
 * La version de x86 ademas rastrea los registros para decir que valor lleva
 * cada uno; eso es propio de esa arquitectura.  Esta sirve para el resto: da
 * el desplazamiento, el texto y la linea, que es lo que la vista necesita para
 * cruzar fuente y codigo.
 *
 * @param code      Bytes.
 * @param code_size Cuantos.
 * @param line_map  Correlacion desplazamiento -> linea que dejo el generador.
 * @param arch      Arquitectura de esos bytes.
 * @return Un array de @c {addr, text, line}.
 */
nlohmann::json
disasm_correlated_generic(const uint8_t *code, size_t code_size,
                          const std::vector<jit::LineMapEntry> &line_map,
                          aot::AotArch arch) {
    nlohmann::json arr = nlohmann::json::array();
    cs_arch cs_a = CS_ARCH_X86;
    cs_mode cs_m = CS_MODE_64;
    if (!code || code_size == 0 || !capstone_for(arch, cs_a, cs_m)) return arr;
    csh handle;
    if (cs_open(cs_a, cs_m, &handle) != CS_ERR_OK) return arr;
    cs_insn *insn = nullptr;
    const size_t count = cs_disasm(handle, code, code_size, 0, 0, &insn);
    for (size_t i = 0; i < count; ++i) {
        const uint64_t off = insn[i].address;
        // La entrada vigente es la ultima que empieza en este desplazamiento o
        // antes; el mapa viene en orden de emision.
        uint32_t linea = 0;
        for (const auto &e : line_map) {
            if (e.byte_offset > off) break;
            linea = e.source_line;
        }
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%04llx",
                      static_cast<unsigned long long>(off));
        std::string texto = insn[i].mnemonic;
        if (insn[i].op_str[0] != '\0')
            texto += std::string(" ") + insn[i].op_str;
        nlohmann::json ji;
        ji["addr"] = buf;
        ji["text"] = std::move(texto);
        ji["line"] = linea;
        arr.push_back(std::move(ji));
    }
    if (count > 0) cs_free(insn, count);
    cs_close(&handle);
    return arr;
}

std::string disasm_x86_64(const uint8_t *code, size_t code_size, uint64_t base,
                          bool mode32 = false) {
    if (!code || code_size == 0) return "(codigo vacio)";
    csh handle;
    if (cs_open(CS_ARCH_X86, mode32 ? CS_MODE_32 : CS_MODE_64, &handle) !=
        CS_ERR_OK)
        return "(Capstone: no se pudo abrir el desensamblador x86)";
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_insn *insn = nullptr;
    const size_t count = cs_disasm(handle, code, code_size, base, 0, &insn);
    std::ostringstream oss;
    if (count > 0) {
        for (size_t i = 0; i < count; ++i) {
            // Offset relativo al inicio (mas estable que una direccion host).
            uint64_t off = insn[i].address - base;
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%04llx",
                          static_cast<unsigned long long>(off));
            oss << buf << "  " << insn[i].mnemonic;
            if (insn[i].op_str[0] != '\0') oss << ' ' << insn[i].op_str;
            oss << '\n';
        }
        cs_free(insn, count);
    } else {
        oss << "(Capstone no pudo desensamblar los bytes generados)\n";
    }
    cs_close(&handle);
    return oss.str();
}

/**
 * @brief Desensambla correlando cada instruccion maquina con su linea fuente.
 *
 * Solo-LSP (vista "Godbolt").  Combina el desensamblado de Capstone (offset
 * + mnemonico) con la @c line_map del codegen (byte_offset -> source_line)
 * para producir un array @c [{addr, text, line}].  La @c line_map viene
 * ordenada ascendentemente por @c byte_offset (orden de emision); para cada
 * instruccion Capstone en @p off se busca la entrada con el mayor
 * @c byte_offset <= off (una @c MInstr puede expandir a varias instrucciones
 * x86, todas atribuidas a su linea).  @c line==0 = sin atribucion (prologo,
 * epilogo, instrs sinteticas).
 *
 * @param code      Bytes del codigo nativo.
 * @param code_size Numero de bytes.
 * @param lm        Tabla byte_offset -> source_line (puede estar vacia).
 * @return Array JSON de @c {addr:"%04x", text, line}.
 */
/**
 * @brief Canonicaliza un registro x86 a su GPR de 64 bits.
 *
 * Para el rastreo de valores (debug-info) se trata @c eax/ax/al igual que
 * @c rax, @c r8d/r8w/r8b igual que @c r8, etc.  Asi @c mov eax, ecx propaga
 * el nombre del valor entre los registros aunque el codegen use el ancho de
 * 32 bits.
 *
 * @param handle Handle Capstone abierto (para @c cs_reg_name).
 * @param reg    Enum del registro (operando).
 * @return Cadena canonica ("rax".."r15") o "" si no es un GPR rastreable.
 */
std::string canon_reg(csh handle, unsigned reg) {
    if (reg == X86_REG_INVALID) return "";
    const char *nm = cs_reg_name(handle, reg);
    if (!nm) return "";
    std::string s = nm;
    static const std::unordered_map<std::string, std::string> kFam = {
        {"rax", "rax"}, {"eax", "rax"},  {"ax", "rax"},   {"al", "rax"},
        {"ah", "rax"},  {"rbx", "rbx"},  {"ebx", "rbx"},  {"bx", "rbx"},
        {"bl", "rbx"},  {"bh", "rbx"},   {"rcx", "rcx"},  {"ecx", "rcx"},
        {"cx", "rcx"},  {"cl", "rcx"},   {"ch", "rcx"},   {"rdx", "rdx"},
        {"edx", "rdx"}, {"dx", "rdx"},   {"dl", "rdx"},   {"dh", "rdx"},
        {"rsi", "rsi"}, {"esi", "rsi"},  {"si", "rsi"},   {"sil", "rsi"},
        {"rdi", "rdi"}, {"edi", "rdi"},  {"di", "rdi"},   {"dil", "rdi"},
        {"rbp", "rbp"}, {"ebp", "rbp"},  {"bp", "rbp"},   {"bpl", "rbp"},
        {"rsp", "rsp"}, {"esp", "rsp"},  {"sp", "rsp"},   {"spl", "rsp"},
        {"r8", "r8"},   {"r8d", "r8"},   {"r8w", "r8"},   {"r8b", "r8"},
        {"r9", "r9"},   {"r9d", "r9"},   {"r9w", "r9"},   {"r9b", "r9"},
        {"r10", "r10"}, {"r10d", "r10"}, {"r10w", "r10"}, {"r10b", "r10"},
        {"r11", "r11"}, {"r11d", "r11"}, {"r11w", "r11"}, {"r11b", "r11"},
        {"r12", "r12"}, {"r12d", "r12"}, {"r12w", "r12"}, {"r12b", "r12"},
        {"r13", "r13"}, {"r13d", "r13"}, {"r13w", "r13"}, {"r13b", "r13"},
        {"r14", "r14"}, {"r14d", "r14"}, {"r14w", "r14"}, {"r14b", "r14"},
        {"r15", "r15"}, {"r15d", "r15"}, {"r15w", "r15"}, {"r15b", "r15"},
    };
    auto it = kFam.find(s);
    return it == kFam.end() ? std::string() : it->second;
}

/// Etiqueta legible de un slot relativo a rbp: "[rbp-0x8]" / "[rbp+0x10]".
std::string frame_label(int64_t disp) {
    char b[32];
    if (disp < 0)
        std::snprintf(b, sizeof(b), "[rbp-0x%llx]",
                      static_cast<unsigned long long>(-disp));
    else
        std::snprintf(b, sizeof(b), "[rbp+0x%llx]",
                      static_cast<unsigned long long>(disp));
    return b;
}

nlohmann::json disasm_x86_64_correlated(
    const uint8_t *code, size_t code_size,
    const std::vector<jit::LineMapEntry> &lm,
    const std::vector<jit::NativeReloc> &relocs,
    const std::vector<std::pair<std::string, std::string>> &arg_seed,
    nlohmann::json *frame_out) {
    nlohmann::json arr = nlohmann::json::array();
    if (!code || code_size == 0) return arr;
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return arr;
    // DETAIL ON: necesitamos los operandos estructurados (reg/mem/imm + acceso)
    // para rastrear que valor con nombre vive en cada registro / slot del
    // frame.
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = nullptr;
    const size_t count = cs_disasm(handle, code, code_size, 0, 0, &insn);
    size_t lm_idx = 0; // cursor en lm (ambos en orden ascendente de offset).

    // Estado del rastreo (debug-info):
    //   regmap[canon]  -> nombre del valor fuente que el registro contiene.
    //   framemap[disp] -> {nombre, tamano} del slot [rbp+disp].
    std::unordered_map<std::string, std::string> regmap;
    struct FSlot {
        std::string name;
        uint16_t size;
        bool seen; // primer offset donde aparece (para orden de salida)
        uint64_t first_off;
    };
    std::map<int64_t, FSlot> framemap;
    // Seed: la convencion de llamada coloca cada argumento en su registro.
    for (const auto &pr : arg_seed)
        if (!pr.first.empty()) regmap[pr.first] = pr.second;

    // Layout del prologo (registros guardados + area reservada).  Tras
    // `mov rbp, rsp`, [rbp+0]=rbp guardado, [rbp+8]=direccion de retorno, y
    // cada `push reg` posterior baja 8 bytes ([rbp-8], [rbp-16], ...).
    bool have_rbp = false;
    int64_t push_off = 0; // offset (rel. rbp) del ultimo push tras rbp
    int64_t reserved_bytes = 0;
    bool reserved_done = false;
    std::vector<nlohmann::json> saved_regs; // {offset,size,kind,name}

    for (size_t i = 0; i < count; ++i) {
        const uint64_t off = insn[i].address; // base 0 -> offset relativo.
        const uint64_t end = off + insn[i].size;
        while (lm_idx + 1 < lm.size() && lm[lm_idx + 1].byte_offset <= off)
            ++lm_idx;
        uint32_t line = 0;
        uint32_t ir_id = 0xFFFFFFFFu;
        if (lm_idx < lm.size() && lm[lm_idx].byte_offset <= off) {
            line = lm[lm_idx].source_line;
            ir_id = lm[lm_idx].ir_id;
        }
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%04llx",
                      static_cast<unsigned long long>(off));
        std::string text = insn[i].mnemonic;
        if (insn[i].op_str[0] != '\0') {
            text += ' ';
            text += insn[i].op_str;
        }

        // --- Rastreo de valores con nombre + frame --------------------------
        std::vector<std::string> ann; // partes del comentario de valores
        auto add_ann = [&](const std::string &s) {
            for (const auto &e : ann)
                if (e == s) return; // dedup
            ann.push_back(s);
        };
        cs_detail *det = insn[i].detail;
        if (det) {
            const cs_x86 &x = det->x86;
            const unsigned id = insn[i].id;
            // --- Layout del prologo -------------------------------------
            if (id == X86_INS_MOV && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG &&
                x.operands[1].type == X86_OP_REG &&
                canon_reg(handle, x.operands[0].reg) == "rbp" &&
                canon_reg(handle, x.operands[1].reg) == "rsp") {
                have_rbp = true; // mov rbp, rsp -> frame pointer establecido
            } else if (id == X86_INS_PUSH && have_rbp && x.op_count == 1 &&
                       x.operands[0].type == X86_OP_REG) {
                push_off -= 8;
                const char *rn = cs_reg_name(handle, x.operands[0].reg);
                nlohmann::json js;
                js["offset"] = push_off;
                js["label"] = frame_label(push_off);
                js["size"] = 8;
                js["kind"] = "saved";
                js["name"] = rn ? rn : "?";
                saved_regs.push_back(std::move(js));
            } else if (id == X86_INS_SUB && have_rbp && !reserved_done &&
                       x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
                       canon_reg(handle, x.operands[0].reg) == "rsp" &&
                       x.operands[1].type == X86_OP_IMM) {
                reserved_bytes = x.operands[1].imm;
                reserved_done = true;
            }
            const bool is_mov = (id == X86_INS_MOV || id == X86_INS_MOVZX ||
                                 id == X86_INS_MOVSX || id == X86_INS_MOVSXD);
            bool handled = false;
            // POP es restauracion de epilogo (callee-saved).  El rastreo es
            // lineal (sin CFG), asi que el `pop rsi` del epilogo del PRIMER
            // bloque -en orden de direcciones- precede a otros bloques donde
            // ese mismo registro callee-saved sigue alojando el valor (p.ej.
            // el parametro durante toda la funcion).  Lo tratamos como
            // no-invalidante para no perder el nombre en bloques posteriores.
            if (id == X86_INS_POP) handled = true;
            if (is_mov && x.op_count == 2) {
                const cs_x86_op &d = x.operands[0];
                const cs_x86_op &s = x.operands[1];
                if (d.type == X86_OP_REG && s.type == X86_OP_REG) {
                    // mov reg, reg : propaga el nombre del origen al destino.
                    std::string dc = canon_reg(handle, d.reg);
                    std::string sc = canon_reg(handle, s.reg);
                    std::string nm = sc.empty() ? "" : regmap[sc];
                    if (!dc.empty()) {
                        if (nm.empty())
                            regmap.erase(dc);
                        else {
                            regmap[dc] = nm;
                            add_ann(dc + " = " + nm);
                        }
                    }
                    handled = true;
                } else if (d.type == X86_OP_REG && s.type == X86_OP_MEM &&
                           canon_reg(handle, s.mem.base) == "rbp") {
                    // mov reg, [rbp+disp] : carga desde un slot conocido.
                    std::string dc = canon_reg(handle, d.reg);
                    auto fit = framemap.find(s.mem.disp);
                    std::string nm =
                        fit == framemap.end() ? "" : fit->second.name;
                    if (!dc.empty()) {
                        if (nm.empty())
                            regmap.erase(dc);
                        else {
                            regmap[dc] = nm;
                            add_ann(dc + " = " + nm);
                        }
                    }
                    handled = true;
                } else if (d.type == X86_OP_MEM &&
                           canon_reg(handle, d.mem.base) == "rbp" &&
                           s.type == X86_OP_REG) {
                    // mov [rbp+disp], reg : guarda un valor con nombre -> slot.
                    std::string sc = canon_reg(handle, s.reg);
                    std::string nm = sc.empty() ? "" : regmap[sc];
                    if (!nm.empty()) {
                        FSlot &fs = framemap[d.mem.disp];
                        if (!fs.seen) {
                            fs.seen = true;
                            fs.first_off = off;
                        }
                        fs.name = nm;
                        fs.size = d.size ? d.size : 8;
                        add_ann(frame_label(d.mem.disp) + " = " + nm);
                    }
                    handled = true;
                } else if (d.type == X86_OP_REG && s.type == X86_OP_IMM) {
                    // mov reg, imm : el registro deja de tener un valor con
                    // nombre.
                    std::string dc = canon_reg(handle, d.reg);
                    if (!dc.empty()) regmap.erase(dc);
                    handled = true;
                }
            }
            if (!handled) {
                // Caso generico: anotar los registros/slots LEIDOS con nombre,
                // luego invalidar los registros ESCRITOS (resultado anonimo).
                for (uint8_t oi = 0; oi < x.op_count; ++oi) {
                    const cs_x86_op &op = x.operands[oi];
                    if (op.type == X86_OP_REG && (op.access & CS_AC_READ)) {
                        std::string c = canon_reg(handle, op.reg);
                        if (!c.empty() && !regmap[c].empty())
                            add_ann(c + " = " + regmap[c]);
                    } else if (op.type == X86_OP_MEM &&
                               canon_reg(handle, op.mem.base) == "rbp") {
                        auto fit = framemap.find(op.mem.disp);
                        if (fit != framemap.end() && !fit->second.name.empty())
                            add_ann(frame_label(op.mem.disp) + " = " +
                                    fit->second.name);
                    }
                }
                for (uint8_t oi = 0; oi < x.op_count; ++oi) {
                    const cs_x86_op &op = x.operands[oi];
                    if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE)) {
                        std::string c = canon_reg(handle, op.reg);
                        if (!c.empty()) regmap.erase(c);
                    }
                }
            }
        }

        // Comentario combinado: simbolo de relocation (call/lea) + valores.
        std::vector<std::string> comments;
        // Buscar la relocation que cubre esta instruccion (call/jmp/lea/movabs
        // a un simbolo propio).  El backend de asm enruta `mov r64, simbolo` a
        // un literal PLACEHOLDER de 64 bits (Keystone no hace fixups de 64
        // bits); ese placeholder aparece crudo en el desensamblado
        // (`0xc0ffee...`). Aqui lo SUSTITUIMOS por el nombre legible del
        // simbolo (estilo Godbolt: `movabs rax, add`), igual que hace el fix
        // del ensamblado.
        const jit::NativeReloc *rrel = nullptr;
        for (const auto &rc : relocs) {
            if (rc.offset >= off && rc.offset < end && !rc.symbol.empty()) {
                rrel = &rc;
                break;
            }
        }
        if (rrel) {
            // Nombre legible: quitar prefijos internos (`fnsym:` = funcion;
            // `rodata.N` = slot de datos) que el cliente no necesita ver.
            std::string sym = rrel->symbol;
            if (sym.rfind("fnsym:", 0) == 0)
                sym = sym.substr(6);
            else if (sym.rfind("rodata.", 0) == 0)
                sym = "rodata[" + sym.substr(7) + "]";
            std::string disp_sym = sym;
            if (rrel->addend) disp_sym += "+" + std::to_string(rrel->addend);
            // Reescribir el operando relocado: sustituir el literal hex por el
            // simbolo.  Caso RIP-relativo (`[rip + 0x..]` / `[rip - 0x..]`) y
            // caso inmediato/branch (`movabs rax, 0x..`, `call 0x..`).
            bool rewrote = false;
            auto repl_hex_at = [&](size_t hexs) {
                size_t hexe = hexs + 2;
                while (hexe < text.size() &&
                       std::isxdigit((unsigned char)text[hexe]))
                    ++hexe;
                if (hexe > hexs + 2) {
                    text.replace(hexs, hexe - hexs, disp_sym);
                    rewrote = true;
                }
            };
            size_t rip = text.find("rip + 0x");
            if (rip == std::string::npos) rip = text.find("rip - 0x");
            if (rip != std::string::npos) {
                repl_hex_at(text.find("0x", rip));
            } else {
                size_t hexs = text.rfind("0x");
                if (hexs != std::string::npos) repl_hex_at(hexs);
            }
            // Si no se pudo reescribir inline, dejar el simbolo como comentario
            // (fallback) para no perder la informacion.
            if (!rewrote) comments.push_back(disp_sym);
        }
        for (const auto &a : ann)
            comments.push_back(a);
        if (!comments.empty()) {
            text += "  ; ";
            for (size_t c = 0; c < comments.size(); ++c) {
                if (c) text += ", ";
                text += comments[c];
            }
        }

        nlohmann::json ji;
        ji["addr"] = buf;
        ji["text"] = std::move(text);
        ji["line"] = line;
        ji["ir_id"] = ir_id; // correlacion exacta op-IR <-> asm (solo-LSP)
        arr.push_back(std::move(ji));
    }
    if (count > 0) cs_free(insn, count);
    cs_close(&handle);

    // Volcar el frame completo, ordenado de la cima (mas cercano a rbp+) hacia
    // abajo: retorno, rbp guardado, registros callee-saved, slots con nombre
    // (spills/locales) y el area reservada.
    if (frame_out) {
        std::vector<nlohmann::json> all;
        if (have_rbp) {
            // Marco estandar: [rbp+8]=retorno, [rbp+0]=rbp guardado.
            nlohmann::json jret;
            jret["offset"] = 8;
            jret["label"] = frame_label(8);
            jret["size"] = 8;
            jret["kind"] = "retaddr";
            jret["name"] = "direccion de retorno";
            all.push_back(std::move(jret));
            nlohmann::json jrbp;
            jrbp["offset"] = 0;
            jrbp["label"] = "[rbp]";
            jrbp["size"] = 8;
            jrbp["kind"] = "saved";
            jrbp["name"] = "rbp";
            all.push_back(std::move(jrbp));
        }
        for (auto &s : saved_regs)
            all.push_back(std::move(s));
        for (const auto &kv : framemap) {
            nlohmann::json js;
            js["offset"] = kv.first; // disp relativo a rbp (negativo = local)
            js["label"] = frame_label(kv.first);
            js["size"] = kv.second.size;
            js["kind"] = "local";
            js["name"] = kv.second.name;
            all.push_back(std::move(js));
        }
        if (reserved_bytes > 0) {
            nlohmann::json jr;
            jr["offset"] = push_off - reserved_bytes;
            jr["label"] = frame_label(push_off - reserved_bytes);
            jr["size"] = reserved_bytes;
            jr["kind"] = "reserved";
            jr["name"] = "area reservada (locales/shadow)";
            all.push_back(std::move(jr));
        }
        // Orden: offset descendente (cima del marco primero).
        std::sort(all.begin(), all.end(), [](const auto &a, const auto &b) {
            return a["offset"].template get<int64_t>() >
                   b["offset"].template get<int64_t>();
        });
        for (auto &e : all)
            frame_out->push_back(std::move(e));
    }
    return arr;
}

/**
 * @brief Recoge las lineas fuente .vx que abarca una funcion IR.
 *
 * Solo-LSP (vista "Godbolt"): el panel SOURCE muestra el codigo de la
 * funcion.  Calcula el rango [min,max] de @c source_line sobre las
 * instrucciones de @p fn (ignorando 0) y extrae esas lineas del documento.
 *
 * @param doc Texto completo del documento .vx.
 * @param fn  Funcion IR.
 * @return Array JSON de @c {line, text} (1-based), vacio si no hay lineas.
 */
nlohmann::json function_source_lines(const std::string &doc,
                                     const ir::IrFunction &fn) {
    uint32_t lo = UINT32_MAX, hi = 0;
    for (const auto &blk : fn.blocks) {
        for (const auto &ins : blk.instrs) {
            if (ins.source_line == 0) continue;
            lo = std::min(lo, ins.source_line);
            hi = std::max(hi, ins.source_line);
        }
    }
    nlohmann::json arr = nlohmann::json::array();
    if (lo == UINT32_MAX || hi < lo) return arr;
    // Trocear el documento en lineas (1-based) y extraer [lo,hi].
    uint32_t cur = 1;
    size_t start = 0;
    for (size_t i = 0; i <= doc.size(); ++i) {
        if (i == doc.size() || doc[i] == '\n') {
            if (cur >= lo && cur <= hi) {
                std::string ln = doc.substr(start, i - start);
                if (!ln.empty() && ln.back() == '\r') ln.pop_back();
                nlohmann::json jl;
                jl["line"] = cur;
                jl["text"] = std::move(ln);
                arr.push_back(std::move(jl));
            }
            start = i + 1;
            ++cur;
            if (cur > hi) break;
        }
    }
    return arr;
}

/**
 * @brief Construye la asociacion argumento -> registro de una funcion.
 *
 * Solo-LSP: el desensamblado no dice que registro lleva cada argumento.
 * Esta tabla la calcula desde @c fn.params (nombres) + la convencion de
 * llamada (orden de los registros de argumento).
 *
 * @param fn        Funcion IR.
 * @param arg_regs  Nombres de los registros de argumento en orden (ABI).
 * @return Array JSON de @c {name, reg}.
 */
nlohmann::json function_args(const ir::IrFunction &fn,
                             const std::vector<const char *> &arg_regs) {
    nlohmann::json arr = nlohmann::json::array();
    for (size_t i = 0; i < fn.params.size() && i < arg_regs.size(); ++i) {
        const ir::IrValueId pid = fn.params[i];
        std::string nm;
        if (pid < fn.values.size()) nm = fn.values[pid].name;
        // Quitar el '%' inicial de los nombres SSA ("%n" -> "n").
        if (!nm.empty() && nm[0] == '%') nm = nm.substr(1);
        if (nm.empty()) nm = "arg" + std::to_string(i);
        nlohmann::json ji;
        ji["name"] = nm;
        ji["reg"] = arg_regs[i];
        arr.push_back(std::move(ji));
    }
    return arr;
}

/**
 * @brief Renderizado corto de una instruccion IR para la correlacion IR<->asm.
 *
 * Solo-LSP: formato compacto "<dst> = <op> <operandos>" (o sin dst), con el
 * nombre de funcion para CALL* y el inmediato para CONST.  Usa los nombres de
 * los valores SSA (ya etiquetados con el nombre de fuente cuando aplica).
 */
std::string ir_short(const ir::IrFunction &fn, const ir::IrInstr &in) {
    auto vn = [&](ir::IrValueId v) -> std::string {
        if (v == ir::IR_NO_VALUE) return "?";
        return v < fn.values.size() ? fn.values[v].name
                                    : ("%" + std::to_string(v));
    };
    // INLINE_ASM: el func_name es el cuerpo asm COMPLETO (multilinea).
    // Volcado en una sola linea es ilegible -> forma compacta con el numero de
    // instrucciones; el cuerpo real se muestra expandido en ir_listing.
    if (in.op == ir::IrOp::INLINE_ASM) {
        int ninstr = 0;
        bool in_tok = false;
        for (char c : in.func_name) {
            if (c == '\n') {
                in_tok = false;
            } else if (c == ';' || c == '/') {
                in_tok = true; // resto de la linea es comentario
            } else if (!in_tok && c != ' ' && c != '\t' && c != ':') {
                // primera no-blanca de la linea: cuenta si no es etiqueta sola
                if (!in_tok) {
                    in_tok = true;
                    ++ninstr; // aproximado (incluye lineas de etiqueta)
                }
            }
        }
        return "inline_asm { " + std::to_string(ninstr) + " lineas }";
    }
    std::string s;
    if (in.dst != ir::IR_NO_VALUE) s += vn(in.dst) + " = ";
    s += ir::ir_op_name(in.op);
    if (!in.func_name.empty()) {
        s += " ";
        s += in.func_name;
    }
    for (size_t k = 0; k < in.operands.size(); ++k) {
        s += (k == 0 ? " " : ", ");
        s += vn(in.operands[k]);
    }
    if (in.op == ir::IrOp::CONST)
        s += " " + std::to_string(static_cast<int64_t>(in.imm));
    return s;
}

/**
 * @brief Construye el mapa linea-de-fuente -> lista de ops IR de esa linea.
 *
 * Solo-LSP: une por @c source_line (clave fiable: tanto el desensamblado como
 * cada IrInstr la llevan).  Omite NOP/PHI (ruido).  Es la base de los modos de
 * correlacion IR<->asm (grupo/panel/3col).
 */
nlohmann::json ir_by_line(const ir::IrFunction &fn) {
    nlohmann::json o = nlohmann::json::object();
    for (const auto &blk : fn.blocks) {
        for (const auto &in : blk.instrs) {
            if (in.source_line == 0) continue;
            if (in.op == ir::IrOp::NOP || in.op == ir::IrOp::PHI) continue;
            o[std::to_string(in.source_line)].push_back(ir_short(fn, in));
        }
    }
    return o;
}

/**
 * @brief Mapa identidad-op-IR -> texto corto (correlacion exacta).
 *
 * Solo-LSP: la identidad es block_index*65536 + instr_pos, la MISMA que estampa
 * el backend vreg en cada MInstr y propaga al line_map.  El cliente cruza el
 * ir_id de cada fila asm con este mapa para mostrar la op IR exacta que la
 * genero.  Omite NOP/PHI (sin identidad util).
 */
nlohmann::json ir_by_id(const ir::IrFunction &fn) {
    nlohmann::json o = nlohmann::json::object();
    for (size_t b = 0; b < fn.blocks.size(); ++b) {
        const auto &instrs = fn.blocks[b].instrs;
        for (size_t p = 0; p < instrs.size(); ++p) {
            const auto &in = instrs[p];
            if (in.op == ir::IrOp::NOP || in.op == ir::IrOp::PHI) continue;
            uint32_t id = static_cast<uint32_t>(b * 65536u + p);
            o[std::to_string(id)] = ir_short(fn, in);
        }
    }
    return o;
}

/**
 * @brief Listado ORDENADO del IR para la columna central de la vista 3col:
 *        por bloque, una fila etiqueta (nombre del bloque) seguida de sus ops.
 *        Cada fila lleva su @c source_line para el cross-highlight.
 *
 * Solo-LSP.  kind: "label" (etiqueta de bloque) | "op" (instruccion IR).
 */
nlohmann::json ir_listing(const ir::IrFunction &fn) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto &blk : fn.blocks) {
        nlohmann::json jl;
        jl["kind"] = "label";
        jl["line"] = 0;
        jl["text"] = blk.name;
        arr.push_back(std::move(jl));
        for (const auto &in : blk.instrs) {
            if (in.op == ir::IrOp::NOP || in.op == ir::IrOp::PHI) continue;
            if (in.op == ir::IrOp::INLINE_ASM) {
                // Expandir el cuerpo asm: una fila por linea (legible), con su
                // linea .vx real (base+1+k); las etiquetas como "label".
                nlohmann::json jh;
                jh["kind"] = "op";
                jh["line"] = in.source_line;
                jh["text"] = "inline_asm {";
                arr.push_back(std::move(jh));
                size_t pos = 0;
                int k = 0;
                const std::string &body = in.func_name;
                while (pos <= body.size()) {
                    size_t nl = body.find('\n', pos);
                    std::string ln = body.substr(pos, nl == std::string::npos
                                                          ? std::string::npos
                                                          : nl - pos);
                    size_t b0 = ln.find_first_not_of(" \t");
                    if (b0 != std::string::npos) {
                        std::string t = ln.substr(b0);
                        while (!t.empty() &&
                               (t.back() == ' ' || t.back() == '\t'))
                            t.pop_back();
                        bool is_lbl = !t.empty() && t.back() == ':';
                        nlohmann::json jo;
                        jo["kind"] = is_lbl ? "label" : "op";
                        jo["line"] = in.source_line + 1 + k;
                        jo["text"] =
                            is_lbl ? t.substr(0, t.size() - 1) : ("  " + t);
                        arr.push_back(std::move(jo));
                    }
                    ++k;
                    if (nl == std::string::npos) break;
                    pos = nl + 1;
                }
                continue;
            }
            nlohmann::json jo;
            jo["kind"] = "op";
            jo["line"] = in.source_line;
            jo["text"] = ir_short(fn, in);
            arr.push_back(std::move(jo));
        }
    }
    return arr;
}

/// Convierte las etiquetas de inline-asm (offset->nombre) a JSON {offset(hex
/// "%04x"), name}, con el mismo formato de offset que las filas asm.
nlohmann::json
asm_labels_json(const std::vector<std::pair<uint32_t, std::string>> &labels) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto &p : labels) {
        char b[16];
        std::snprintf(b, sizeof(b), "%04x", p.first);
        nlohmann::json j;
        j["offset"] = b;
        j["name"] = p.second;
        arr.push_back(std::move(j));
    }
    return arr;
}

/**
 * @brief Anota una instruccion .vel con los valores con nombre de sus registros
 *        VM (rastreo R0..R15), analogo al de x86.  Modifica @p line in-place
 *        anadiendo "  ; rN = nombre" y actualiza @p vr (mapa rN -> nombre).
 *
 * Solo-LSP: seed con los args en r1..rN; @c mov propaga, las ALU/escritores
 * invalidan su destino y anotan las lecturas con nombre, las ramas anotan sus
 * operandos, @c call invalida r0.
 */
void annotate_vel(std::string &line,
                  std::unordered_map<std::string, std::string> &vr,
                  std::vector<std::string> &vstack) {
    std::vector<std::string> toks;
    std::string cur;
    for (char c : line) {
        if (c == ' ' || c == '\t' || c == ',') {
            if (!cur.empty()) {
                toks.push_back(cur);
                cur.clear();
            }
        } else
            cur.push_back(c);
    }
    if (!cur.empty()) toks.push_back(cur);
    if (toks.empty()) return;
    const std::string &mn = toks[0];
    auto isvr = [](const std::string &t) -> bool {
        if (t.size() < 2 || t[0] != 'r') return false;
        for (size_t i = 1; i < t.size(); ++i)
            if (!std::isdigit((unsigned char)t[i])) return false;
        return true;
    };
    std::vector<std::string> regs;
    for (size_t i = 1; i < toks.size(); ++i)
        if (isvr(toks[i])) regs.push_back(toks[i]);
    std::vector<std::string> ann;
    auto add = [&](const std::string &s) {
        for (const auto &e : ann)
            if (e == s) return;
        ann.push_back(s);
    };
    auto starts = [&](const char *p) { return mn.rfind(p, 0) == 0; };
    const bool is_branch = starts("jmp") || starts("cmpjmp") ||
                           starts("cmpu") || starts("cmps") || starts("cmp");
    const bool is_call = starts("call");
    const bool is_mov = (mn == "mov" || mn == "movh" || mn == "movc" ||
                         mn == "movch" || mn == "movcl");
    if (mn == "push" && regs.size() == 1) {
        // Guarda el nombre (modelo de pila) para que el pop lo restaure; es
        // lectura -> anotar si tiene nombre.
        auto it = vr.find(regs[0]);
        vstack.push_back(it != vr.end() ? it->second : std::string());
        if (it != vr.end()) add(regs[0] + " = " + it->second);
    } else if (mn == "pop" && regs.size() == 1) {
        if (!vstack.empty()) {
            std::string nm = vstack.back();
            vstack.pop_back();
            if (!nm.empty()) {
                vr[regs[0]] = nm;
                add(regs[0] + " = " + nm);
            } else
                vr.erase(regs[0]);
        } else
            vr.erase(regs[0]);
    } else if (is_mov && regs.size() >= 1) {
        const std::string dst = regs[0];
        if (regs.size() >= 2) { // mov rD, rS -> propaga
            auto it = vr.find(regs[1]);
            if (it != vr.end()) {
                vr[dst] = it->second;
                add(dst + " = " + it->second);
            } else
                vr.erase(dst);
        } else
            vr.erase(dst); // mov rD, imm / @Absolute(...)
    } else if (is_branch) {
        for (const auto &rg : regs) {
            auto it = vr.find(rg);
            if (it != vr.end()) add(rg + " = " + it->second);
        }
    } else if (is_call) {
        for (const auto &rg : regs) {
            auto it = vr.find(rg);
            if (it != vr.end()) add(rg + " = " + it->second);
        }
        vr.erase("r0"); // el retorno (r0) queda desconocido
    } else if (!regs.empty()) {
        // Escritor generico: regs[0]=destino, resto lecturas.
        for (size_t i = 1; i < regs.size(); ++i) {
            auto it = vr.find(regs[i]);
            if (it != vr.end()) add(regs[i] + " = " + it->second);
        }
        vr.erase(regs[0]);
    }
    if (!ann.empty()) {
        line += "  ; ";
        for (size_t i = 0; i < ann.size(); ++i) {
            if (i) line += ", ";
            line += ann[i];
        }
    }
}

/**
 * @brief Mapea el nombre de tier textual al enum AOT.
 * @param tier "bare" | "embed" | "full" (insensible a otras formas).
 * @return Tier correspondiente (BARE por defecto).
 */
aot::Tier tier_from_str(const std::string &tier) {
    if (tier == "full") return aot::Tier::FULL;
    if (tier == "embed") return aot::Tier::EMBED;
    return aot::Tier::BARE;
}

/**
 * @brief Nombre legible de un kind de relocation nativa AOT.
 * @param k Kind de la relocation.
 * @return Cadena ASCII.
 */
const char *reloc_kind_str(jit::NativeReloc::Kind k) {
    switch (k) {
    case jit::NativeReloc::Kind::CALL_REL32: return "CALL_REL32";
    case jit::NativeReloc::Kind::ABS64: return "ABS64";
    case jit::NativeReloc::Kind::DATA_REL32: return "DATA_REL32";
    }
    return "?";
}

} // namespace

Inspector::Inspector(AnalysisEngine &engine, DocumentStore &docs) noexcept
    : engine_(engine), docs_(docs) {}

Inspector::~Inspector() = default;

namespace {
/// Forward-decls: las definiciones viven mas abajo (mismo TU, namespace
/// anonimo).  Reabrir @c namespace{} refiere a la MISMA entidad de enlace
/// interno, asi que @c Inspector::bytecode puede usarlas antes de definirse.
std::vector<std::string> ir_split_lines(const std::string &s);
std::string vel_extract_fn(const std::string &vel, const std::string &fn);
} // namespace

nlohmann::json Inspector::bytecode(const std::string &uri,
                                   const std::string &function,
                                   const InspectTarget &target) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    // El bytecode VM es arch-agnostico; el @c target->os solo selecciona las
    // ramas @Target.  Con target activo recompilamos fresco bajo el guard.
    InspectTargetGuard tguard(target);
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;
    // Sin funcion (panel del inspector): modulo entero, texto plano.
    if (function.empty()) {
        // any_override(), no active(): pedir otro nivel de optimizacion es otra
        // pregunta aunque la maquina sea la misma.  Con active() se devolvia el
        // analisis cacheado y los cuatro niveles daban el mismo texto.
        if (target.any_override()) {
            vx::CompileResult res =
                compile_document(uri, text, view_options(target));
            return {{"text", res.vel_text}};
        }
        const auto an_ref = engine_.analyze_document(uri, text);
        const DocAnalysis &an = *an_ref;
        return {{"text", an.result.vel_text}};
    }

    // Por-funcion (hover): vista correlada linea .vx -> bytecode generado,
    // igual estilo que JIT/AOT.  Recompilamos con emit_debug para tener los
    // marcadores `// @line N` y atribuir cada instruccion .vel a su linea.
    // Cache por (uri, hash, fn) -- recompilar es barato pero no en cada frame.
    const uint64_t hsh = fnv1a_hash(text);
    const std::string key = uri + "|" + std::to_string(hsh) +
                            "|bc-gb:" + function + target.cache_key();
    std::string guardado;
    if (view_cached(key, guardado)) return nlohmann::json::parse(guardado);

    vx::CompileOptions opts;
    opts.module_name = "main";
    opts.emit_debug = true;        // emite `// @line N` en el .vel
    opts.emit_comptime_fns = true; // incluir comptime fns (inspeccion)
    vx::CompileResult res = compile_document(uri, text, opts);
    const std::string block = vel_extract_fn(res.vel_text, function);

    // Parsear el IR una vez: fuente + args + ir_by_line, y sembrar el rastreo
    // de registros VM (arg i -> r(i+1)) para las anotaciones del bytecode.
    nlohmann::json src = nlohmann::json::array();
    nlohmann::json args = nlohmann::json::array();
    nlohmann::json irbl = nlohmann::json::object();
    nlohmann::json irlst = nlohmann::json::array();
    std::unordered_map<std::string, std::string> vregmap;
    std::vector<std::string> vstack; // modelo de pila para push/pop
    ir::IrModule mod;
    if (parse_post_opt_module(res, mod)) {
        const ir::IrFunction *fn = pick_function(mod, function);
        if (fn) {
            src = function_source_lines(text, *fn);
            args = function_args(*fn, {"R1", "R2", "R3", "R4", "R5", "R6", "R7",
                                       "R8", "R9", "R10", "R11", "R12"});
            irbl = ir_by_line(*fn);
            irlst = ir_listing(*fn);
            for (size_t i = 0; i < args.size(); ++i)
                vregmap["r" + std::to_string(i + 1)] =
                    args[i]["name"].get<std::string>();
        }
    }

    // Parsear el bloque: cada `// @line N` fija la linea actual; cada
    // instruccion la hereda; las etiquetas van con linea 0 (contexto).  Cada
    // instruccion se anota con los valores con nombre de sus registros VM.
    nlohmann::json asm_lines = nlohmann::json::array();
    int cur_line = 0;
    for (const auto &raw : ir_split_lines(block)) {
        size_t s = raw.find_first_not_of(" \t");
        if (s == std::string::npos) continue; // linea en blanco
        std::string t = raw.substr(s);
        if (t.rfind("// @line ", 0) == 0) {
            cur_line = std::atoi(t.c_str() + 9);
            continue;
        }
        if (t.rfind("//", 0) == 0)
            continue; // otros comentarios (parametros, etc.)
        const bool is_label =
            (raw[0] != ' ' && raw[0] != '\t' && !t.empty() && t.back() == ':');
        if (!is_label)
            annotate_vel(t, vregmap, vstack); // rastreo de registros VM
        nlohmann::json ji;
        ji["addr"] = ""; // el bytecode no tiene offset de byte como el x86
        ji["text"] = t;
        ji["line"] = is_label ? 0 : cur_line;
        asm_lines.push_back(std::move(ji));
    }

    // Post-pase: las etiquetas (line 0) heredan la linea del bloque que
    // encabezan -- forward-fill desde la siguiente instruccion con linea>0,
    // o backward desde la previa.  Asi `factorial_ret:` cae en el bloque del
    // `return` en vez de la inexistente "linea 0".
    {
        int n = static_cast<int>(asm_lines.size());
        for (int i = 0; i < n; ++i) {
            if (asm_lines[i]["line"].get<int>() != 0) continue;
            int fill = 0;
            for (int j = i + 1; j < n; ++j) {
                int lj = asm_lines[j]["line"].get<int>();
                if (lj != 0) {
                    fill = lj;
                    break;
                }
            }
            if (fill == 0) // no hay siguiente; usar la previa
                for (int j = i - 1; j >= 0; --j) {
                    int lj = asm_lines[j]["line"].get<int>();
                    if (lj != 0) {
                        fill = lj;
                        break;
                    }
                }
            if (fill != 0) asm_lines[i]["line"] = fill;
        }
    }

    nlohmann::json out;
    out["text"] = block;
    out["function"] = function;
    out["asm_lines"] = std::move(asm_lines);
    out["source"] = std::move(src);
    out["ir_by_line"] = std::move(irbl);
    out["ir_listing"] = std::move(irlst);
    out["args"] = std::move(args);
    view_store(key, out.dump());
    return out;
}

nlohmann::json Inspector::ir(const std::string &uri, const std::string &phase,
                             const InspectTarget &target) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    // @Target(os) del target: recompilamos fresco bajo el guard para que las
    // ramas por-OS se seleccionen segun el target (el arch no afecta al IR).
    InspectTargetGuard tguard(target);
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;

    if (phase == "pre") {
        // El IR pre-opt NO esta en el CompileResult cacheado por defecto:
        // exige recompilar con emit_ir_preopt.  Cachear por (uri, hash).
        const uint64_t h = fnv1a_hash(text);
        const std::string key =
            uri + "|" + std::to_string(h) + "|ir-pre" + target.cache_key();
        std::string guardado;
        if (view_cached(key, guardado)) return {{"text", guardado}};

        vx::CompileOptions opts = view_options(target);
        opts.emit_ir_preopt = true;
        vx::CompileResult res = compile_document(uri, text, opts);
        if (res.ir_module_cache_bytes_preopt.empty())
            return {{"error", "no se pudo generar el IR pre-optimizacion"}};
        ir::IrModule mod;
        if (!ir::parse_ir_module_cache(res.ir_module_cache_bytes_preopt, mod))
            return {
                {"error", "no se pudo deserializar el IR pre-optimizacion"}};
        std::ostringstream oss;
        ir::ir_print(mod, oss);
        std::string rendered = oss.str();
        view_store(key, rendered);
        return {{"text", std::move(rendered)}};
    }

    //  "post" (o cualquier otra): con target activo recompilar fresco
    // (el cache del motor es host); si no, reutilizar el cache del motor.
    ir::IrModule mod;
    bool got = false;
    if (target.any_override()) {
        vx::CompileResult res =
            compile_document(uri, text, view_options(target));
        got = parse_post_opt_module(res, mod);
    } else {
        const auto an_ref = engine_.analyze_document(uri, text);
        const DocAnalysis &an = *an_ref;
        got = parse_post_opt_module(an.result, mod);
    }
    if (!got)
        return {{"error", "el modulo no produjo IR (revisa los diagnosticos)"}};
    std::ostringstream oss;
    ir::ir_print(mod, oss);
    return {{"text", oss.str()}};
}

namespace {

/// Parte @p s en lineas (sin el '\n').
std::vector<std::string> ir_split_lines(const std::string &s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i <= s.size()) {
        size_t nl = s.find('\n', i);
        if (nl == std::string::npos) {
            if (i < s.size()) out.push_back(s.substr(i));
            break;
        }
        out.push_back(s.substr(i, nl - i));
        i = nl + 1;
    }
    return out;
}

/// Extrae el bloque @c @function <fn>( ... ) del dump @p dump (con sus
/// @c @template_of/@type_args precedentes), hasta el siguiente @c @function o
/// EOF.  Si no se encuentra (o fn vacio), devuelve el dump entero.
std::string ir_extract_fn(const std::string &dump, const std::string &fn) {
    if (fn.empty()) return dump;
    std::vector<std::string> lines = ir_split_lines(dump);
    const std::string want = "@function " + fn + "(";
    int found = -1;
    for (int i = 0; i < (int)lines.size(); ++i)
        if (lines[i].rfind(want, 0) == 0) {
            found = i;
            break;
        }
    if (found < 0) return dump;
    int start = found;
    while (start > 0 && (lines[start - 1].rfind("@template_of", 0) == 0 ||
                         lines[start - 1].rfind("@type_args", 0) == 0))
        --start;
    int end = (int)lines.size();
    for (int i = found + 1; i < (int)lines.size(); ++i)
        if (lines[i].rfind("@function ", 0) == 0) {
            end = i;
            break;
        }
    std::string out;
    for (int i = start; i < end; ++i) {
        out += lines[i];
        out += "\n";
    }
    return out;
}

/// Extrae el bloque .vel (bytecode textual) de UNA funcion del volcado del
/// modulo.  Las funciones se delimitan por una etiqueta a columna 0
/// @c "<fn>:"; las etiquetas internas del cuerpo llevan el prefijo
/// @c "<fn>_" (entry/while_header/ret/...).  El bloque va desde @c "<fn>:"
/// hasta la siguiente etiqueta de nivel superior (una que NO empieza por
/// @c "<fn>_").  Para funciones comptime el frontend emite @c "__macro_<fn>:",
/// asi que probamos ambos nombres.  Si no se encuentra, devuelve el volcado
/// entero (degrada con elegancia).
std::string vel_extract_fn(const std::string &vel, const std::string &fn) {
    if (fn.empty()) return vel;
    std::vector<std::string> lines = ir_split_lines(vel);
    // Helper: ¿la linea es una etiqueta a columna 0?  Devuelve el nombre
    // (sin los dos puntos) o "" si no lo es.
    auto label_of = [](const std::string &s) -> std::string {
        if (s.empty() || s[0] == ' ' || s[0] == '\t') return "";
        if (s.back() != ':') return "";
        std::string id = s.substr(0, s.size() - 1);
        for (char c : id)
            if (!(std::isalnum((unsigned char)c) || c == '_' || c == '.'))
                return "";
        return id;
    };
    // Buscar la etiqueta de la funcion (nombre directo o __macro_<fn>).
    std::string base;
    int found = -1;
    for (int i = 0; i < (int)lines.size(); ++i) {
        std::string lab = label_of(lines[i]);
        if (lab.empty()) continue;
        if (lab == fn || lab == "__macro_" + fn) {
            base = lab;
            found = i;
            break;
        }
    }
    if (found < 0) return vel;
    const std::string pfx = base + "_";
    int end = (int)lines.size();
    for (int i = found + 1; i < (int)lines.size(); ++i) {
        std::string lab = label_of(lines[i]);
        if (lab.empty()) continue;
        // Etiqueta de nivel superior distinta (no es interna de esta fn).
        if (lab != base && lab.rfind(pfx, 0) != 0) {
            end = i;
            break;
        }
    }
    std::string out;
    for (int i = found; i < end; ++i) {
        out += lines[i];
        out += "\n";
    }
    return out;
}

/// Una fila del diff alineado.  kind: "same" (l==r), "del" (solo l, eliminado),
/// "add" (solo r, generado), "chg" (l->r, cambiado).
struct DiffRow {
    std::string kind;
    std::string l, r;
};

/// Diff por lineas (LCS) que produce FILAS ALINEADAS.  Empareja una racha de
/// eliminaciones seguida de una de adiciones en filas "chg" (cambiado), de modo
/// que la version sin/optimizada queden lado a lado.  Capea el coste O(N*M).
std::vector<DiffRow> ir_diff_rows(const std::string &a, const std::string &b) {
    std::vector<std::string> A = ir_split_lines(a), B = ir_split_lines(b);
    const int n = (int)A.size(), m = (int)B.size();
    // Secuencia bruta de operaciones (same/del/add).
    std::vector<DiffRow> ops;
    if ((long long)n * m > 4000000LL) {
        for (int i = 0; i < n; ++i)
            ops.push_back({"del", A[i], ""});
        for (int j = 0; j < m; ++j)
            ops.push_back({"add", "", B[j]});
    } else {
        std::vector<std::vector<int>> L(n + 1, std::vector<int>(m + 1, 0));
        for (int i = n - 1; i >= 0; --i)
            for (int j = m - 1; j >= 0; --j)
                L[i][j] = (A[i] == B[j]) ? L[i + 1][j + 1] + 1
                                         : std::max(L[i + 1][j], L[i][j + 1]);
        int i = 0, j = 0;
        while (i < n && j < m) {
            if (A[i] == B[j]) {
                ops.push_back({"same", A[i], B[i >= 0 ? j : j]});
                ops.back().r = B[j];
                ++i;
                ++j;
            } else if (L[i + 1][j] >= L[i][j + 1]) {
                ops.push_back({"del", A[i], ""});
                ++i;
            } else {
                ops.push_back({"add", "", B[j]});
                ++j;
            }
        }
        while (i < n) {
            ops.push_back({"del", A[i], ""});
            ++i;
        }
        while (j < m) {
            ops.push_back({"add", "", B[j]});
            ++j;
        }
    }
    // Emparejar rachas del+add consecutivas en filas "chg".
    std::vector<DiffRow> rows;
    for (size_t k = 0; k < ops.size();) {
        if (ops[k].kind == "del") {
            size_t d0 = k;
            while (k < ops.size() && ops[k].kind == "del")
                ++k;
            size_t a0 = k;
            while (k < ops.size() && ops[k].kind == "add")
                ++k;
            size_t nd = a0 - d0, na = k - a0;
            size_t paired = nd < na ? nd : na;
            for (size_t p = 0; p < paired; ++p)
                rows.push_back({"chg", ops[d0 + p].l, ops[a0 + p].r});
            for (size_t p = paired; p < nd; ++p)
                rows.push_back({"del", ops[d0 + p].l, ""});
            for (size_t p = paired; p < na; ++p)
                rows.push_back({"add", "", ops[a0 + p].r});
        } else {
            rows.push_back(ops[k]);
            ++k;
        }
    }
    return rows;
}

} // namespace

nlohmann::json Inspector::ir_diff(const std::string &uri,
                                  const std::string &function) {
    nlohmann::json pre = ir(uri, "pre");
    nlohmann::json post = ir(uri, "post");
    if (pre.contains("error")) return pre;
    if (post.contains("error")) return post;
    const std::string pre_block =
        ir_extract_fn(pre.value("text", std::string()), function);
    const std::string post_block =
        ir_extract_fn(post.value("text", std::string()), function);
    std::vector<DiffRow> rows = ir_diff_rows(pre_block, post_block);
    nlohmann::json jrows = nlohmann::json::array();
    for (const auto &row : rows)
        jrows.push_back({{"k", row.kind}, {"l", row.l}, {"r", row.r}});
    nlohmann::json out;
    out["rows"] = std::move(jrows);
    out["function"] = function;
    return out;
}

nlohmann::json Inspector::complexity(const std::string &uri) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    const auto an_ref = engine_.analyze_document(uri, *docs_.text(uri));
    const DocAnalysis &an = *an_ref;
    ir::IrModule mod;
    if (!parse_post_opt_module(an.result, mod))
        return {{"error", "el modulo no produjo IR (revisa los diagnosticos)"}};

    // Coste PARCIAL + composicion interprocedural (coste efectivo real).
    analyze::ModuleCost mc = analyze::analyze_module(mod);
    analyze::compose_interproc(mc);

    nlohmann::json arr = nlohmann::json::array();
    for (const auto &cr : mc.functions) {
        nlohmann::json jf;
        jf["name"] = cr.function;
        // El nombre INTERNO identifica; el escrito es el que se ensena.
        jf["display"] = vx::demangle_symbol(cr.function);
        jf["partial"] = analyze::cost_class_str(cr.big_o);
        jf["total"] = analyze::cost_class_str(cr.total_class);
        // Por su NOMBRE, no por el numero del enum: el numero obliga a que el
        // otro lado conozca la numeracion -- dos sitios sabiendo lo mismo -- y
        // ademas no se puede ensenar tal cual.
        jf["confidence"] = analyze::confidence_str(cr.confidence);
        jf["total_confidence"] = analyze::confidence_str(cr.total_confidence);
        jf["max_loop_depth"] = cr.max_loop_depth;
        jf["recursive"] = cr.is_recursive;
        jf["divide_conquer"] = cr.is_divide_conquer;
        jf["declared"] = cr.declared_expr; // vacio => sin contrato @complexity.
        jf["contract_mismatch"] = cr.contract_mismatch;
        arr.push_back(std::move(jf));
    }
    nlohmann::json out;
    out["functions"] = std::move(arr);
    return out;
}

nlohmann::json Inspector::function_report(const std::string &uri) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    const auto text_ref = docs_.text(uri);
    const auto an_ref = engine_.analyze_document(uri, *text_ref);
    const DocAnalysis &an = *an_ref;
    ir::IrModule mod;
    if (!parse_post_opt_module(an.result, mod))
        return {{"error", "el modulo no produjo IR (revisa los diagnosticos)"}};

    // Lo que cuesta, con el cierre interprocedural.
    analyze::ModuleCost mc = analyze::analyze_module(mod);
    analyze::compose_interproc(mc);

    // Lo que HACE, medido sobre el codigo que sale, para el objetivo activo.
    std::string fp_os, fp_arch;
    vx::get_aot_condcomp_target(fp_os, fp_arch);
    if (fp_arch.empty()) fp_arch = "x86_64";
    std::vector<analyze::FunctionFingerprint> huellas =
        analyze::compute_module_fingerprints(mod, fp_arch);
    analyze::compose_fingerprints(huellas, &an.result.contracts, &mod);
    const std::vector<analyze::ContractCheck> veredictos =
        analyze::verify_contracts(huellas, an.result.contracts);

    // Y si el modo nativo puede con ella.
    std::unordered_map<std::string, std::vector<const aot::AotIncompat *>>
        problemas;
    aot::AotTarget objetivo_aot;
    objetivo_aot.tier = tier_from_str("bare");
    const aot::AotCompatReport compat =
        aot::aot_analyze_module(mod, objetivo_aot);
    for (const auto &iss : compat.issues)
        problemas[iss.fn_name].push_back(&iss);

    // Indice por nombre para cruzar las tres cosas.
    std::unordered_map<std::string, const analyze::FunctionFingerprint *>
        por_fn;
    for (const auto &h : huellas)
        por_fn[h.function] = &h;

    nlohmann::json arr = nlohmann::json::array();
    for (const auto &cr : mc.functions) {
        nlohmann::json jf;
        jf["name"] = cr.function;
        jf["display"] = vx::demangle_symbol(cr.function);
        jf["line"] = 0u;
        for (const auto &fn : mod.functions) {
            if (fn.name == cr.function) {
                jf["line"] = first_source_line(fn);
                break;
            }
        }

        nlohmann::json coste;
        coste["partial"] = analyze::cost_class_str(cr.big_o);
        coste["total"] = analyze::cost_class_str(cr.total_class);
        coste["confidence"] = analyze::confidence_str(cr.confidence);
        coste["totalConfidence"] = analyze::confidence_str(cr.total_confidence);
        coste["loops"] = cr.max_loop_depth;
        coste["recursive"] = cr.is_recursive;
        coste["declared"] = cr.declared_expr;
        coste["mismatch"] = cr.contract_mismatch;
        jf["cost"] = std::move(coste);

        // Lo MEDIDO.  -1 no existe aqui: o se sabe el numero o se dice que los
        // efectos no se conocen del todo, que es otra cosa.
        auto ith = por_fn.find(cr.function);
        if (ith != por_fn.end()) {
            const analyze::FunctionFingerprint &h = *ith->second;
            nlohmann::json m;
            m["allocPartial"] = h.alloc_sites;
            m["allocTotal"] = h.alloc_sites_total;
            m["stackPartial"] = static_cast<uint64_t>(h.stack_bytes);
            /* La pila que no se puede acotar se DICE, no se manda como numero.
             *
             * `STACK_UNBOUNDED` es `UINT64_MAX`, un valor perfectamente valido
             * usado de centinela: mandado tal cual, al otro lado se lee como un
             * tamano y se pinta "18446744073709552000 B", que no es que la
             * funcion gaste dieciocho trillones de bytes sino que NO SE SABE
             * cuanto gasta -- aqui, porque hay un `asm` cuyo marco no se ve --.
             */
            const bool acotada =
                h.stack_bytes_total != analyze::STACK_UNBOUNDED;
            m["stackBounded"] = acotada;
            if (acotada)
                m["stackTotal"] = static_cast<uint64_t>(h.stack_bytes_total);
            m["throws"] = h.throws_total;
            m["panics"] = h.panics_total;
            m["pure"] = h.pure;
            m["recursive"] = h.recursive;
            m["effectsKnown"] = h.effects_known;
            m["frameOpaque"] = h.frame_opaque;
            m["dynamicCall"] = h.has_dynamic_call;
            jf["measured"] = std::move(m);
        }

        // Lo DECLARADO, solo lo que se declaro.
        auto itc = an.result.contracts.find(cr.function);
        if (itc != an.result.contracts.end() && itc->second.any()) {
            const analyze::FunctionContracts &c = itc->second;
            nlohmann::json d;
            if (c.pure) d["pure"] = true;
            if (c.nothrow) d["nothrow"] = true;
            if (c.nopanic) d["nopanic"] = true;
            if (c.alloc_partial >= 0) d["allocPartial"] = c.alloc_partial;
            if (c.alloc_total >= 0) d["allocTotal"] = c.alloc_total;
            if (c.stack_partial >= 0) d["stackPartial"] = c.stack_partial;
            if (c.stack_total >= 0) d["stackTotal"] = c.stack_total;
            jf["declared"] = std::move(d);
        }

        // El veredicto de cada contrato declarado.
        nlohmann::json checks = nlohmann::json::array();
        for (const auto &ck : veredictos) {
            if (ck.function != cr.function) continue;
            nlohmann::json jc;
            jc["contract"] = ck.contract;
            jc["status"] = ck.status == analyze::ContractCheck::OK ? "cumple"
                           : ck.status == analyze::ContractCheck::VIOLATED
                               ? "incumple"
                               : "no se puede decidir";
            jc["detail"] = ck.detail;
            checks.push_back(std::move(jc));
        }
        jf["checks"] = std::move(checks);

        nlohmann::json aot;
        auto itp = problemas.find(cr.function);
        aot["ok"] = itp == problemas.end();
        nlohmann::json motivos = nlohmann::json::array();
        if (itp != problemas.end()) {
            for (const aot::AotIncompat *iss : itp->second) {
                nlohmann::json ji;
                ji["op"] = ir::ir_op_name(iss->op);
                ji["reason"] = iss->reason;
                ji["line"] = iss->source_line;
                motivos.push_back(std::move(ji));
            }
        }
        aot["issues"] = std::move(motivos);
        jf["aot"] = std::move(aot);

        arr.push_back(std::move(jf));
    }

    nlohmann::json out;
    out["functions"] = std::move(arr);
    return out;
}

namespace {

/// @brief Una instruccion desensamblada con su rol en el flujo de control.
struct AsmInsn {
    uint64_t off = 0;           ///< offset relativo al inicio del codigo.
    std::string text;           ///< "mnemonico operandos".
    bool is_cond_jmp = false;   ///< salto condicional (je, jne, jl, ...).
    bool is_uncond_jmp = false; ///< salto incondicional (jmp).
    bool is_ret = false;        ///< retorno (ret / iret).
    bool has_target = false;    ///< el salto tiene destino inmediato resuelto.
    uint64_t target = 0;        ///< offset destino del salto (si has_target).
};

/// @brief Escapa un texto para un nodo mermaid entre comillas (["..."]).
std::string mermaid_escape(const std::string &s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        if (c == '"')
            o += '\'';
        else if (c == '<')
            o += "&lt;";
        else if (c == '>')
            o += "&gt;";
        else
            o += c;
    }
    return o;
}

/// @brief Escapa un texto para una etiqueta graphviz entre comillas.
std::string graphviz_escape(const std::string &s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\') o += '\\';
        o += c;
    }
    return o;
}

/**
 * @brief Desensambla los bytes nativos anotando el rol de control de cada
 *        instruccion (salto cond/incond, ret, destino inmediato).
 *
 * Usa Capstone con detalle activo: para los saltos directos el destino es el
 * operando inmediato (absoluto con base 0 = offset relativo).  @return la
 * lista de instrucciones, vacia si Capstone no pudo abrir/decodificar.
 */
std::vector<AsmInsn> disasm_for_cfg(const uint8_t *code, size_t code_size,
                                    bool mode32) {
    std::vector<AsmInsn> out;
    if (!code || code_size == 0) return out;
    csh handle;
    if (cs_open(CS_ARCH_X86, mode32 ? CS_MODE_32 : CS_MODE_64, &handle) !=
        CS_ERR_OK)
        return out;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = nullptr;
    const size_t count = cs_disasm(handle, code, code_size, 0, 0, &insn);
    for (size_t i = 0; i < count; ++i) {
        AsmInsn a;
        a.off = insn[i].address;
        a.text = insn[i].mnemonic;
        if (insn[i].op_str[0] != '\0') {
            a.text += ' ';
            a.text += insn[i].op_str;
        }
        const cs_detail *d = insn[i].detail;
        bool is_jump = false, is_ret = false;
        if (d) {
            for (uint8_t g = 0; g < d->groups_count; ++g) {
                if (d->groups[g] == CS_GRP_JUMP)
                    is_jump = true;
                else if (d->groups[g] == CS_GRP_RET ||
                         d->groups[g] == CS_GRP_IRET)
                    is_ret = true;
            }
        }
        a.is_ret = is_ret;
        if (is_jump) {
            // 'jmp' es incondicional; el resto (je/jne/jl/...) condicionales.
            const std::string m = insn[i].mnemonic;
            a.is_uncond_jmp = (m == "jmp");
            a.is_cond_jmp = !a.is_uncond_jmp;
            // Destino inmediato directo (base 0 -> offset relativo).
            if (d && d->x86.op_count >= 1 &&
                d->x86.operands[0].type == X86_OP_IMM) {
                a.has_target = true;
                a.target = static_cast<uint64_t>(d->x86.operands[0].imm);
            }
        }
        out.push_back(std::move(a));
    }
    if (count > 0) cs_free(insn, count);
    cs_close(&handle);
    return out;
}

/**
 * @brief Construye un CFG del codigo maquina (bloques basicos) en mermaid o
 *        graphviz.
 *
 * Los lideres de bloque son: el offset 0, las etiquetas emitidas por el
 * backend (@p labels), los destinos de salto y la instruccion siguiente a
 * cada salto/ret.  Las aristas salen del terminador de cada bloque: salto
 * incondicional -> destino; condicional -> destino (T) + caida (F); ret ->
 * sin aristas; resto -> caida al siguiente bloque.
 */
std::string
native_cfg_diagram(const std::vector<AsmInsn> &ins,
                   const std::vector<std::pair<uint32_t, std::string>> &labels,
                   const std::string &fn_name, const std::string &format) {
    if (ins.empty()) return std::string();

    // Mapa offset -> etiqueta del backend (nombre de bloque IR).
    std::map<uint64_t, std::string> lbl;
    for (const auto &p : labels)
        lbl[p.first] = p.second;

    // Fin del codigo = offset de la ultima instruccion + su hueco al siguiente.
    // Para delimitar el ultimo bloque usamos un centinela > al ultimo offset.
    const uint64_t code_end = ins.back().off + 1;

    // 1) Recolectar lideres.
    std::set<uint64_t> leaders;
    leaders.insert(ins.front().off);
    for (const auto &p : labels)
        leaders.insert(p.first);
    for (size_t i = 0; i < ins.size(); ++i) {
        const AsmInsn &a = ins[i];
        if ((a.is_cond_jmp || a.is_uncond_jmp) && a.has_target &&
            a.target < code_end)
            leaders.insert(a.target);
        if (a.is_cond_jmp || a.is_uncond_jmp || a.is_ret) {
            if (i + 1 < ins.size()) leaders.insert(ins[i + 1].off);
        }
    }

    // 2) Indexar instrucciones por offset para localizar el rango de cada
    //    bloque [leader, siguiente_leader).
    std::vector<uint64_t> ord(leaders.begin(), leaders.end());
    auto block_id = [&](uint64_t off) -> int {
        // Bloque cuyo leader es el mayor <= off.
        int id = -1;
        for (size_t i = 0; i < ord.size(); ++i) {
            if (ord[i] <= off)
                id = static_cast<int>(i);
            else
                break;
        }
        return id;
    };

    // 3) Para cada bloque, sus instrucciones + su terminador.
    struct Block {
        uint64_t start = 0;
        std::vector<const AsmInsn *> body;
    };
    std::vector<Block> blocks(ord.size());
    for (size_t i = 0; i < ord.size(); ++i)
        blocks[i].start = ord[i];
    for (const AsmInsn &a : ins) {
        int id = block_id(a.off);
        if (id >= 0) blocks[id].body.push_back(&a);
    }

    auto node_name = [&](size_t i) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "B%zu", i);
        return std::string(buf);
    };
    auto block_label = [&](const Block &b) {
        auto it = lbl.find(b.start);
        char hx[16];
        std::snprintf(hx, sizeof(hx), "0x%llx",
                      static_cast<unsigned long long>(b.start));
        return it != lbl.end() ? it->second : std::string(hx);
    };

    std::ostringstream out;
    if (format == "graphviz") {
        out << "digraph cfg_asm {\n";
        out << "  label=\"CFG nativo: " << graphviz_escape(fn_name) << "\";\n";
        out << "  labelloc=t;\n";
        out << "  node [shape=box, fontname=\"monospace\", fontsize=10];\n";
        for (size_t i = 0; i < blocks.size(); ++i) {
            std::string body = block_label(blocks[i]) + ":\\l";
            for (const AsmInsn *a : blocks[i].body)
                body += graphviz_escape(a->text) + "\\l";
            out << "  " << node_name(i) << " [label=\"" << body << "\"];\n";
        }
        // Aristas.
        for (size_t i = 0; i < blocks.size(); ++i) {
            if (blocks[i].body.empty()) continue;
            const AsmInsn *term = blocks[i].body.back();
            auto edge = [&](uint64_t tgt, const char *lab) {
                // Destino fuera del codigo de la funcion (tail-call / salto
                // externo resuelto por reloc): no es una arista del CFG local.
                if (tgt >= code_end) return;
                int id = block_id(tgt);
                if (id < 0) return;
                out << "  " << node_name(i) << " -> " << node_name(id);
                if (lab && lab[0]) out << " [label=\"" << lab << "\"]";
                out << ";\n";
            };
            if (term->is_ret) {
                // sin aristas.
            } else if (term->is_uncond_jmp && term->has_target) {
                edge(term->target, "");
            } else if (term->is_cond_jmp && term->has_target) {
                edge(term->target, "T");
                if (i + 1 < blocks.size()) edge(blocks[i + 1].start, "F");
            } else if (i + 1 < blocks.size()) {
                edge(blocks[i + 1].start, "");
            }
        }
        out << "}\n";
        return out.str();
    }

    // mermaid (por defecto).
    out << "flowchart TD\n";
    for (size_t i = 0; i < blocks.size(); ++i) {
        std::string body = block_label(blocks[i]) + ":";
        for (const AsmInsn *a : blocks[i].body)
            body += "<br/>" + mermaid_escape(a->text);
        out << "  " << node_name(i) << "[\"" << body << "\"]\n";
    }
    for (size_t i = 0; i < blocks.size(); ++i) {
        if (blocks[i].body.empty()) continue;
        const AsmInsn *term = blocks[i].body.back();
        auto edge = [&](uint64_t tgt, const char *lab) {
            // Destino fuera del codigo de la funcion (tail-call / salto externo
            // resuelto por reloc): no es una arista del CFG local.
            if (tgt >= code_end) return;
            int id = block_id(tgt);
            if (id < 0) return;
            out << "  " << node_name(i) << " -->";
            if (lab && lab[0]) out << "|" << lab << "|";
            out << ' ' << node_name(id) << "\n";
        };
        if (term->is_ret) {
            // sin aristas.
        } else if (term->is_uncond_jmp && term->has_target) {
            edge(term->target, "");
        } else if (term->is_cond_jmp && term->has_target) {
            edge(term->target, "T");
            if (i + 1 < blocks.size()) edge(blocks[i + 1].start, "F");
        } else if (i + 1 < blocks.size()) {
            edge(blocks[i + 1].start, "");
        }
    }
    return out.str();
}

} // namespace

nlohmann::json Inspector::diagram(const std::string &uri,
                                  const std::string &kind,
                                  const std::string &format, bool cost,
                                  const InspectTarget &target,
                                  const std::string &function) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    // El @c target->os selecciona las ramas @Target en las fases IR/vel del
    // diagrama.  El guard se aplica a la recompilacion que hace la generacion.
    InspectTargetGuard tguard(target);
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;

    // Validar kind y format antes de recompilar.
    const bool kind_ok =
        (kind == "ast" || kind == "ir-pre" || kind == "ir-post" ||
         kind == "vel" || kind == "asm" || kind == "types");
    if (!kind_ok)
        return {
            {"error", "kind invalido (use ast|ir-pre|ir-post|vel|asm|types)"}};
    const bool fmt_ok =
        (format == "mermaid" || format == "graphviz" || format == "html");
    if (!fmt_ok)
        return {{"error", "format invalido (use mermaid|graphviz|html)"}};

    // ---- CFG del codigo maquina nativo (kind == "asm") ---------------------
    // No pasa por los flags dump_* del frontend: compila la funcion elegida al
    // backend vreg (el de produccion) y construye el grafo de bloques basicos
    // desde el desensamblado de Capstone.
    if (kind == "asm") {
        const std::string akey = uri + "|" + std::to_string(fnv1a_hash(text)) +
                                 "|diagasm:" + format + ":" + function +
                                 target.cache_key();
        std::string guardado;
        if (view_cached(akey, guardado)) return {{"text", guardado}};

        ir::IrModule mod;
        bool got_ir = false;
        if (target.any_override()) {
            vx::CompileResult cr =
                compile_document(uri, text, view_options(target));
            got_ir = parse_post_opt_module(cr, mod);
        } else {
            const auto an_ref = engine_.analyze_document(uri, text);
            const DocAnalysis &an = *an_ref;
            got_ir = parse_post_opt_module(an.result, mod);
        }
        if (!got_ir)
            return {
                {"error", "el modulo no produjo IR (revisa los diagnosticos)"}};

        const ir::IrFunction *fn = pick_function(mod, function);
        if (!fn && !function.empty()) {
            // La funcion puede ser comptime (elidida del IR normal): recompilar
            // incluyendola.
            vx::CompileOptions co;
            co.module_name = "main";
            co.emit_comptime_fns = true;
            vx::CompileResult cr2 = vx::compile_vx_source(text, uri, co);
            ir::IrModule m2;
            if (parse_post_opt_module(cr2, m2)) {
                mod = std::move(m2);
                fn = pick_function(mod, function);
            }
        }
        if (!fn)
            return {{"error", function.empty()
                                  ? "el modulo no tiene funciones compilables"
                                  : "'" + function + "' no esta en el IR"}};

        std::vector<jit::NativeReloc> relocs;
        std::vector<std::pair<uint32_t, std::string>> asm_labels;
        std::vector<uint8_t> bytes;
        try {
            bytes = jit::vreg_compile_native(
                *fn, /*resolve_call=*/{}, /*ent=*/{}, /*resolve_native=*/{},
                /*resolve_symbol=*/{}, &relocs, /*pic=*/true,
                /*target_sysv=*/target_is_sysv(target),
                /*mode32=*/false, jit::FloatIsa::SSE2,
                /*emit_line_map=*/false, nullptr, &asm_labels);
        } catch (...) {
            return {{"error", "el codegen vreg lanzo una excepcion para '" +
                                  fn->name + "'"}};
        }
        if (bytes.empty())
            return {{"unsupported", true},
                    {"reason", "la funcion '" + fn->name +
                                   "' usa operaciones IR aun no soportadas por "
                                   "el backend vreg"}};

        std::vector<AsmInsn> ins =
            disasm_for_cfg(bytes.data(), bytes.size(), /*mode32=*/false);
        if (ins.empty())
            return {{"error", "Capstone no pudo desensamblar el codigo"}};
        std::string body =
            native_cfg_diagram(ins, asm_labels, fn->name,
                               format == "graphviz" ? "graphviz" : "mermaid");
        if (body.empty()) return {{"error", "el CFG nativo salio vacio"}};
        // Para HTML envolvemos el mermaid en una pagina minima con el runtime.
        std::string out_text;
        if (format == "html") {
            out_text =
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
                "<script "
                "src=\"https://cdn.jsdelivr.net/npm/mermaid/dist/"
                "mermaid.min.js\"></script>"
                "<script>mermaid.initialize({startOnLoad:true});</script>"
                "</head><body><pre class=\"mermaid\">\n" +
                body + "\n</pre></body></html>\n";
        } else {
            out_text = std::move(body);
        }
        view_store(akey, out_text);
        return {{"text", out_text}};
    }

    // Cache por (uri, hash, kind, format, cost): la generacion de diagramas
    // recompila con flags concretos -> no repetir peticiones identicas.
    const uint64_t h = fnv1a_hash(text);
    const std::string key = uri + "|" + std::to_string(h) + "|diag:" + kind +
                            ":" + format + ":" + (cost ? "1" : "0") +
                            target.cache_key();
    std::string guardado;
    if (view_cached(key, guardado)) return {{"text", guardado}};

    // Activar SOLO el flag de la vista pedida (uno por kind x format).
    vx::CompileOptions opts;
    opts.module_name = "main";
    // El coste Big-O se anota siempre en los diagramas IR (el parametro `cost`
    // se conserva en la clave de cache por compatibilidad de la peticion LSP).
    (void)cost;
    if (format == "mermaid") {
        if (kind == "ast")
            opts.dump_mermaid_ast = true;
        else if (kind == "ir-pre")
            opts.dump_mermaid_ir_pre = true;
        else if (kind == "ir-post")
            opts.dump_mermaid_ir_post = true;
        else if (kind == "types")
            opts.dump_mermaid_types = true;
        else
            opts.dump_mermaid_vel = true;
    } else if (format == "graphviz") {
        if (kind == "ast")
            opts.dump_graphviz_ast = true;
        else if (kind == "ir-pre")
            opts.dump_graphviz_ir_pre = true;
        else if (kind == "ir-post")
            opts.dump_graphviz_ir_post = true;
        else if (kind == "types")
            opts.dump_graphviz_types = true;
        else
            opts.dump_graphviz_vel = true;
    } else { // html
        if (kind == "ast")
            opts.dump_html_ast = true;
        else if (kind == "ir-pre")
            opts.dump_html_ir_pre = true;
        else if (kind == "ir-post")
            opts.dump_html_ir_post = true;
        else if (kind == "types")
            opts.dump_html_types = true;
        else
            opts.dump_html_vel = true;
    }

    vx::CompileResult res = compile_document(uri, text, opts);
    // Seleccionar el campo del CompileResult que corresponde a la vista.
    std::string out_text;
    if (format == "mermaid") {
        if (kind == "ast")
            out_text = res.mermaid_ast;
        else if (kind == "ir-pre")
            out_text = res.mermaid_ir_pre;
        else if (kind == "ir-post")
            out_text = res.mermaid_ir_post;
        else if (kind == "types")
            out_text = res.mermaid_types;
        else
            out_text = res.mermaid_vel;
    } else if (format == "graphviz") {
        if (kind == "ast")
            out_text = res.graphviz_ast;
        else if (kind == "ir-pre")
            out_text = res.graphviz_ir_pre;
        else if (kind == "ir-post")
            out_text = res.graphviz_ir_post;
        else if (kind == "types")
            out_text = res.graphviz_types;
        else
            out_text = res.graphviz_vel;
    } else {
        if (kind == "ast")
            out_text = res.html_ast;
        else if (kind == "ir-pre")
            out_text = res.html_ir_pre;
        else if (kind == "ir-post")
            out_text = res.html_ir_post;
        else if (kind == "types")
            out_text = res.html_types;
        else
            out_text = res.html_vel;
    }

    if (out_text.empty())
        return {
            {"error",
             "el diagrama salio vacio (revisa los diagnosticos del fuente)"}};
    view_store(key, out_text);
    return {{"text", std::move(out_text)}};
}

nlohmann::json Inspector::functions(const std::string &uri) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    const auto an_ref = engine_.analyze_document(uri, *docs_.text(uri));
    const DocAnalysis &an = *an_ref;
    ir::IrModule mod;
    if (!parse_post_opt_module(an.result, mod))
        return {{"error", "el modulo no produjo IR (revisa los diagnosticos)"}};

    nlohmann::json arr = nlohmann::json::array();
    for (const auto &fn : mod.functions) {
        // Saltar stubs nativos y funciones macro-compiladas (no son del
        // codigo del usuario en el sentido habitual).
        if (fn.is_native || fn.is_macro_compiled) continue;
        nlohmann::json jf;
        jf["name"] = fn.name;
        jf["display"] = vx::demangle_symbol(fn.name);
        jf["line"] = first_source_line(fn);
        arr.push_back(std::move(jf));
    }
    nlohmann::json out;
    out["functions"] = std::move(arr);
    return out;
}

nlohmann::json Inspector::aot_compat(const std::string &uri,
                                     const std::string &tier) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    // El IR del modo NATIVO, no el del interprete: son distintos para el mismo
    // fuente, y preguntar por el equivocado da un veredicto sobre un binario
    // que no es el que se va a generar.
    const auto build_ref = aot_build(uri, *docs_.text(uri));
    const AotBuild &build = *build_ref;
    ir::IrModule mod;
    if (build.ir_bytes.empty() ||
        !ir::parse_ir_module_cache(build.ir_bytes, mod))
        return {{"error", "el modulo no produjo IR en modo nativo (revisa los "
                          "diagnosticos)"}};

    aot::AotTarget target;
    target.tier = tier_from_str(tier);
    aot::AotCompatReport report = aot::aot_analyze_module(mod, target);

    nlohmann::json issues = nlohmann::json::array();
    for (const auto &iss : report.issues) {
        nlohmann::json ji;
        ji["fn_name"] = iss.fn_name;
        ji["fn_display"] = vx::demangle_symbol(iss.fn_name);
        ji["source_line"] = iss.source_line;
        ji["op"] = ir::ir_op_name(iss.op);
        ji["reason"] = iss.reason;
        issues.push_back(std::move(ji));
    }
    nlohmann::json ok = nlohmann::json::array();
    for (const auto &name : report.ok_functions)
        ok.push_back(name);

    nlohmann::json out;
    out["tier"] = tier.empty() ? std::string("bare") : tier;
    out["compatible"] = report.compatible;
    out["issues"] = std::move(issues);
    out["ok_functions"] = std::move(ok);
    return out;
}

nlohmann::json Inspector::jit_asm(const std::string &uri,
                                  const std::string &function,
                                  const InspectTarget &target) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    // El JIT es x86-64 host; el @c target->os solo selecciona las ramas
    // @Target y la ABI mostrada.  Con un target activo recompilamos fresco
    // bajo el guard para que la seleccion @Target sea la del target.
    InspectTargetGuard tguard(target);
    const auto doc_text_ref = docs_.text(uri);
    const std::string &doc_text = *doc_text_ref;
    ir::IrModule mod;
    bool got_ir = false;
    if (target.any_override()) {
        vx::CompileResult cr =
            compile_document(uri, doc_text, view_options(target));
        got_ir = parse_post_opt_module(cr, mod);
    } else {
        const auto an_ref = engine_.analyze_document(uri, doc_text);
        const DocAnalysis &an = *an_ref;
        got_ir = parse_post_opt_module(an.result, mod);
    }
    if (!got_ir)
        return {{"error", "el modulo no produjo IR (revisa los diagnosticos)"}};

    const ir::IrFunction *fn = pick_function(mod, function);
    if (!fn && !function.empty()) {
        // Fallback: la funcion puede ser @c comptime (no-macro), que el
        // frontend elide del IR normal.  Recompilar incluyendola para
        // poder inspeccionar su codegen.
        vx::CompileOptions co;
        co.module_name = "main";
        co.emit_comptime_fns = true;
        vx::CompileResult cr2 = vx::compile_vx_source(doc_text, uri, co);
        ir::IrModule m2;
        if (parse_post_opt_module(cr2, m2)) {
            mod = std::move(m2);
            fn = pick_function(mod, function);
        }
    }
    if (!fn) {
        if (!function.empty())
            return {{"unsupported", true},
                    {"reason",
                     "'" + function +
                         "' no esta en el IO de runtime: puede ser una funcion "
                         "comptime recursiva (se evalua en compilacion; el "
                         "resultado se calcula en el call site) o haber sido "
                         "inlineada/eliminada por el optimizador"}};
        return {{"error", "el modulo no tiene funciones compilables"}};
    }

    // Backend VREG moderno (linear-scan, el mismo que produccion), NO el
    // selector de slots legacy: soporta recursion, llamadas, branches, etc.
    // Para la VISTA usamos el codegen HOST_LEAF (misma seleccion de
    // instrucciones + regalloc que el JIT real; solo difieren prologo y la
    // ABI de las CALL).  Pedimos la tabla linea<->asm para la vista correlada.
    std::vector<jit::NativeReloc> relocs;
    std::vector<jit::LineMapEntry> line_map;
    std::vector<std::pair<uint32_t, std::string>> asm_labels;
    std::vector<uint8_t> bytes;
    try {
        bytes = jit::vreg_compile_native(
            *fn, /*resolve_call=*/{}, /*ent=*/{}, /*resolve_native=*/{},
            /*resolve_symbol=*/{}, &relocs, /*pic=*/true,
            /*target_sysv=*/target_is_sysv(target),
            /*mode32=*/false, jit::FloatIsa::SSE2,
            /*emit_line_map=*/true, &line_map, &asm_labels);
    } catch (...) {
        return {{"error", "el codegen JIT (vreg) lanzo una excepcion para '" +
                              fn->name + "'"}};
    }
    if (bytes.empty())
        return {
            {"unsupported", true},
            {"reason", "la funcion '" + fn->name +
                           "' usa operaciones IR aun no soportadas por el "
                           "backend vreg (float/strings/algunos builtins)"}};

    std::string text = disasm_x86_64(bytes.data(), bytes.size(), 0);
    nlohmann::json args = function_args(
        *fn,
        target_is_sysv(target)
            ? std::vector<const char *>{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
            : std::vector<const char *>{"rcx", "rdx", "r8", "r9"});
    std::vector<std::pair<std::string, std::string>> seed;
    for (const auto &a : args)
        seed.emplace_back(a["reg"].get<std::string>(),
                          a["name"].get<std::string>());
    nlohmann::json frame = nlohmann::json::array();
    nlohmann::json instrs = disasm_x86_64_correlated(
        bytes.data(), bytes.size(), line_map, relocs, seed, &frame);
    nlohmann::json src = function_source_lines(*docs_.text(uri), *fn);

    nlohmann::json out;
    out["text"] = std::move(text);
    out["function"] = fn->name;
    out["bytes"] = static_cast<uint64_t>(bytes.size());
    out["instructions"] = static_cast<uint64_t>(line_map.size());
    out["asm_lines"] = std::move(instrs);
    out["source"] = std::move(src);
    out["frame"] = std::move(frame);
    out["ir_by_line"] = ir_by_line(*fn);
    out["ir_by_id"] = ir_by_id(*fn);
    {
        nlohmann::json bn = nlohmann::json::array();
        for (const auto &blk : fn->blocks)
            bn.push_back(blk.name);
        out["block_names"] = std::move(bn);
    }
    out["ir_listing"] = ir_listing(*fn);
    out["asm_labels"] = asm_labels_json(asm_labels);
    out["args"] = std::move(args);
    return out;
}

nlohmann::json Inspector::aot_asm(const std::string &uri,
                                  const std::string &function,
                                  const InspectTarget &target) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    // La vista AOT por target: aplicar @Target(os) + ABI SysV/Win64 (fmt) +
    // codegen x86-64/x86-32 (arch).  Con target activo recompilamos con el
    // lowering AOT nativo (native_poo) bajo el guard para reflejar el target.
    InspectTargetGuard tguard(target);
    const bool sysv = target_is_sysv(target);
    const bool mode32 = target_is_mode32(target);
    const auto doc_text_ref = docs_.text(uri);
    const std::string &doc_text = *doc_text_ref;
    ir::IrModule mod;
    // Siempre el IR del modo NATIVO, haya objetivo explicito o no.  Antes, sin
    // objetivo, esta vista desensamblaba el IR del INTERPRETE: ensenaba codigo
    // maquina que el modo nativo no genera, porque el mismo fuente baja
    // distinto en cada modo.  Y sin objetivo es el caso por defecto.
    const auto build_ref =
        aot_build(uri, doc_text,
                  target.any_override() ? target.cache_key() : "", target.opt);
    const AotBuild &build = *build_ref;
    const bool got_ir = !build.ir_bytes.empty() &&
                        ir::parse_ir_module_cache(build.ir_bytes, mod);
    if (!got_ir)
        return {{"error", "el modulo no produjo IR en modo nativo (revisa los "
                          "diagnosticos)"}};

    const ir::IrFunction *fn = pick_function(mod, function);
    if (!fn && !function.empty()) {
        // Fallback: la funcion puede ser @c comptime (no-macro), que el
        // frontend elide del IR normal.  Recompilar incluyendola para
        // poder inspeccionar su codegen.
        vx::CompileOptions co;
        co.module_name = "main";
        co.emit_comptime_fns = true;
        // Tambien aqui el lowering nativo: es la vista del modo nativo.
        co.native_poo = true;
        vx::CompileResult cr2 = vx::compile_vx_source(doc_text, uri, co);
        ir::IrModule m2;
        if (parse_post_opt_module(cr2, m2)) {
            mod = std::move(m2);
            fn = pick_function(mod, function);
        }
    }
    if (!fn) {
        if (!function.empty())
            return {{"unsupported", true},
                    {"reason",
                     "'" + function +
                         "' no esta en el IO de runtime: puede ser una funcion "
                         "comptime recursiva (se evalua en compilacion; el "
                         "resultado se calcula en el call site) o haber sido "
                         "inlineada/eliminada por el optimizador"}};
        return {{"error", "el modulo no tiene funciones compilables"}};
    }

    // Primero comprobar compatibilidad AOT (tier BARE: el subset mas
    // estricto, lo que el codegen nativo aislado puede materializar).
    aot::AotTarget aot_tgt;
    aot_tgt.tier = aot::Tier::BARE;
    std::vector<aot::AotIncompat> issues;
    if (!aot::aot_analyze_function(*fn, aot_tgt, issues)) {
        std::string reason =
            "la funcion '" + fn->name + "' no es compatible con AOT bare";
        if (!issues.empty()) {
            reason += ": ";
            reason += ir::ir_op_name(issues.front().op);
            reason += " (";
            reason += issues.front().reason;
            reason += ")";
        }
        return {{"incompatible", true}, {"reason", reason}};
    }

    // Compilar por el MISMO backend que usa la compilacion anticipada de
    // verdad.  Antes esta vista llamaba al generador por debajo y sin
    // resolutores, y entonces cualquier funcion con un literal de cadena --
    // casi todas -- se declaraba "no soportada" aunque el modo nativo la
    // compilase sin una queja: el selector no puede resolver el simbolo y
    // renuncia, mientras que por esta via el mismo simbolo sale como
    // reubicacion, que es justo lo que un objeto necesita.
    std::vector<jit::NativeReloc> relocs;
    std::vector<jit::LineMapEntry> line_map;
    std::vector<std::pair<uint32_t, std::string>> asm_labels;
    std::vector<uint8_t> bytes;
    // La arquitectura que se pidio ver, no la del anfitrion: el compilador
    // genera para varias y esta vista existe para poder mirarlas.
    const aot::AotArch arco = arch_from_name(target.arch);
    std::unique_ptr<aot::NativeBackend> backend =
        aot::make_native_backend(arco);
    if (!backend)
        return {{"error", "no hay generador de codigo nativo para esa "
                          "arquitectura"}};
    aot::NativeCompileOpts nopts;
    nopts.pic = true;
    nopts.target_sysv = sysv;
    nopts.mode32 = mode32;
    // Lo que se pidio ver: el juego de instrucciones de coma flotante y la
    // microarquitectura cambian lo que el generador se permite emitir, asi que
    // son parte de la pregunta, no del entorno.
    nopts.fisa = float_isa_from_str(target.float_isa);
    nopts.cpu = target.cpu;
    nopts.want_line_map = true;
    try {
        aot::NativeCompileResult ncr = backend->compile_function(*fn, nopts);
        bytes = std::move(ncr.bytes);
        relocs = std::move(ncr.relocs);
        line_map = std::move(ncr.line_map);
    } catch (...) {
        return {{"error",
                 "el codegen AOT lanzo una excepcion para '" + fn->name + "'"}};
    }
    if (bytes.empty()) {
        // El selector deja escrito QUE operacion le hizo renunciar.  Decirlo
        // es la diferencia entre un aviso que se puede investigar y uno que
        // solo dice que no.
        const std::string motivo = jit::vreg_ultimo_motivo();
        return {
            {"incompatible", true},
            {"reason", "la funcion '" + fn->name +
                           "' no esta soportada por el generador nativo" +
                           (motivo.empty() ? std::string() : ": " + motivo)}};
    }

    std::string text = disasm_native(bytes.data(), bytes.size(), 0, arco);
    // Los registros por los que llegan los argumentos son propios de cada
    // convencion: SysV y Win64 en x86-64, y AAPCS64 en aarch64.
    const bool es_arm64 = (arco == aot::AotArch::ARM64);
    nlohmann::json args = function_args(
        *fn, es_arm64 ? std::vector<const char *>{"x0", "x1", "x2", "x3", "x4",
                                                  "x5", "x6", "x7"}
                      : (sysv ? std::vector<const char *>{"rdi", "rsi", "rdx",
                                                          "rcx", "r8", "r9"}
                              : std::vector<const char *>{"rcx", "rdx", "r8",
                                                          "r9"}));
    std::vector<std::pair<std::string, std::string>> seed;
    for (const auto &a : args)
        seed.emplace_back(a["reg"].get<std::string>(),
                          a["name"].get<std::string>());
    nlohmann::json frame = nlohmann::json::array();
    // Vista correlada: instruccion a instruccion, con su linea del fuente.
    // Solo x86-64 lleva ademas el rastreo de registros y el marco de pila --
    // eso es propio de esa arquitectura --; el resto sale correlado igual, que
    // es lo que la vista necesita para cruzar fuente y codigo.
    nlohmann::json instrs =
        (arco == aot::AotArch::X86_64)
            ? disasm_x86_64_correlated(bytes.data(), bytes.size(), line_map,
                                       relocs, seed, &frame)
            : disasm_correlated_generic(bytes.data(), bytes.size(), line_map,
                                        arco);
    nlohmann::json src = function_source_lines(*docs_.text(uri), *fn);

    nlohmann::json jrelocs = nlohmann::json::array();
    for (const auto &r : relocs) {
        nlohmann::json jr;
        jr["offset"] = r.offset;
        jr["kind"] = reloc_kind_str(r.kind);
        jr["symbol"] = r.symbol;
        jr["addend"] = r.addend;
        jrelocs.push_back(std::move(jr));
    }

    nlohmann::json out;
    out["text"] = std::move(text);
    out["function"] = fn->name;
    out["bytes"] = static_cast<uint64_t>(bytes.size());
    out["instructions"] = static_cast<uint64_t>(line_map.size());
    out["relocs"] = std::move(jrelocs);
    // Solo-LSP: correlacion fuente <-> asm para la vista godbolt.
    out["asm_lines"] = std::move(instrs);
    out["source"] = std::move(src);
    out["frame"] = std::move(frame);
    out["ir_by_line"] = ir_by_line(*fn);
    out["ir_by_id"] = ir_by_id(*fn);
    {
        nlohmann::json bn = nlohmann::json::array();
        for (const auto &blk : fn->blocks)
            bn.push_back(blk.name);
        out["block_names"] = std::move(bn);
    }
    out["ir_listing"] = ir_listing(*fn);
    out["asm_labels"] = asm_labels_json(asm_labels);
    out["args"] = std::move(args);
    return out;
}

namespace {

/// @brief Cuenta errores y warnings de un CompileResult (para el reporte de
///        modos).  @return {errores, warnings}.
std::pair<size_t, size_t> count_diags(const vx::CompileResult &res) {
    size_t err = 0, warn = 0;
    for (const auto &d : res.diagnostics.all()) {
        if (d.level == vx::DiagLevel::ERR)
            ++err;
        else if (d.level == vx::DiagLevel::WARN)
            ++warn;
    }
    return {err, warn};
}

} // namespace

nlohmann::json Inspector::asa(const std::string &uri) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;
    const auto an_ref = engine_.analyze_document(uri, text);
    const DocAnalysis &an = *an_ref;
    ir::IrModule mod;
    if (!parse_post_opt_module(an.result, mod))
        return {{"error", "el modulo no produjo IR (revisa los diagnosticos)"}};

    /* El asm es un dominio mas, pero su productor vive junto a la base de datos
     * de instrucciones: se da de alta desde aqui, que es quien la tiene, igual
     * que hace la linea de ordenes.  El alta es idempotente. */
    analyze::register_asm_producer();

    analysis::asa::FactStore almacen;
    const std::vector<analysis::asa::ProductionSummary> resumenes =
        /* POST-optimizacion, y lo dice el propio `parse_post_opt_module` de
         * arriba: esta vista ensena lo que se sabe del codigo que de verdad se
         * va a emitir. */
        analysis::asa::produce(mod, almacen, {},
                               analysis::asa::kStagePostOpt);

    /* La vista del subsistema escribe a un fichero abierto, no a una cadena, y
     * asi debe seguir: quien decide como se ensena el conocimiento es el, no
     * cada consumidor.  Se le da un temporal y se lee de vuelta. */
    const std::filesystem::path ruta =
        std::filesystem::temp_directory_path() /
        ("vesta_asa_" + std::to_string(fnv1a_hash(uri + text)) + ".txt");
    std::string volcado;
    {
#if defined(_WIN32)
        FILE *salida = nullptr;
        if (fopen_s(&salida, ruta.string().c_str(), "w+b") != 0)
            salida = nullptr;
#else
        FILE *salida = std::fopen(ruta.string().c_str(), "w+b");
#endif
        if (salida == nullptr)
            return {{"error", "no se pudo abrir un fichero temporal para el "
                              "volcado del ASA"}};
        analysis::asa::print_dump(almacen, resumenes, salida);
        std::fflush(salida);
        std::rewind(salida);
        char buf[8192];
        size_t leidos = 0;
        while ((leidos = std::fread(buf, 1, sizeof(buf), salida)) > 0)
            volcado.append(buf, leidos);
        std::fclose(salida);
    }
    std::error_code ec;
    std::filesystem::remove(ruta, ec); // best-effort: no es un fallo si queda.

    nlohmann::json out;
    out["text"] = std::move(volcado);
    return out;
}

namespace {

/**
 * @brief Linea del fuente a la que pertenece un hecho.
 *
 * Los hechos hablan del programa ya bajado -- de un valor, de un bloque, de una
 * instruccion --, y el editor solo entiende de lineas.  La traduccion la da el
 * propio intermedio, que arrastra la linea de la que salio cada instruccion.
 *
 * @param mod    Modulo intermedio del que salieron los hechos.
 * @param sujeto De quien habla el hecho.
 * @return La linea (contando desde uno), o 0 si no se puede atar a ninguna.
 */
uint32_t linea_del_sujeto(const ir::IrModule &mod,
                          const analysis::asa::Subject &sujeto) {
    using Clase = analysis::asa::Subject::Kind;
    if (sujeto.function == nullptr || *sujeto.function == '\0') return 0;

    const ir::IrFunction *fn = nullptr;
    for (const auto &f : mod.functions) {
        if (f.name == sujeto.function) {
            fn = &f;
            break;
        }
    }
    if (fn == nullptr) return 0;

    // La primera linea de la funcion sirve de respaldo para todo lo que hable
    // de ella entera.
    uint32_t primera = 0;
    uint32_t posicion = 0;
    for (const auto &blk : fn->blocks) {
        for (const auto &in : blk.instrs) {
            if (primera == 0 && in.source_line > 0) primera = in.source_line;
            switch (sujeto.kind) {
            case Clase::Value:
                if (in.dst == sujeto.id && in.source_line > 0)
                    return in.source_line;
                break;
            case Clase::Instruction:
                if (posicion == sujeto.id && in.source_line > 0)
                    return in.source_line;
                break;
            default: break;
            }
            ++posicion;
        }
        if (sujeto.kind == Clase::Block &&
            static_cast<uint32_t>(&blk - &fn->blocks[0]) == sujeto.id &&
            !blk.instrs.empty()) {
            for (const auto &in : blk.instrs)
                if (in.source_line > 0) return in.source_line;
        }
    }
    return primera;
}

/**
 * @brief De QUE habla un hecho, dicho con el codigo que lo produce.
 *
 * "valor" no identifica nada: en una sola linea puede haber ocho, y saber que
 * "un valor" vale entre 0 y 65535 no dice cual ni sirve para nada.  Lo que si
 * lo identifica es la operacion que lo define -- @c %12 @c = @c add @c %7, @c
 * 40 --, que ademas se puede buscar en la vista del IR.
 *
 * @param mod    Modulo del que salieron los hechos.
 * @param sujeto De quien habla el hecho.
 * @return La operacion que lo define, o vacio si no se puede situar.
 */
std::string texto_del_sujeto(const ir::IrModule &mod,
                             const analysis::asa::Subject &sujeto) {
    using Clase = analysis::asa::Subject::Kind;
    if (sujeto.kind != Clase::Value && sujeto.kind != Clase::Instruction)
        return std::string();
    if (sujeto.function == nullptr || *sujeto.function == '\0')
        return std::string();

    const ir::IrFunction *fn = nullptr;
    for (const auto &f : mod.functions) {
        if (f.name == sujeto.function) {
            fn = &f;
            break;
        }
    }
    if (fn == nullptr) return std::string();

    uint32_t posicion = 0;
    for (const auto &blk : fn->blocks) {
        for (const auto &in : blk.instrs) {
            const bool es = (sujeto.kind == Clase::Value)
                                ? (in.dst == sujeto.id)
                                : (posicion == sujeto.id);
            if (es) {
                std::ostringstream oss;
                ir::print_instr(oss, *fn, in);
                std::string t = oss.str();
                // Sin el salto final ni la sangria: va en una celda.
                while (!t.empty() && (t.back() == '\n' || t.back() == '\r'))
                    t.pop_back();
                size_t ini = t.find_first_not_of(" \t");
                return ini == std::string::npos ? t : t.substr(ini);
            }
            ++posicion;
        }
    }
    /* Un valor sin instruccion que lo defina es un PARAMETRO: entra ya hecho.
     * Decirlo es mejor que dejar la celda vacia, que es lo que hacia parecer
     * que el hecho no era de nada. */
    if (sujeto.kind == Clase::Value && sujeto.id < fn->params.size())
        return "parametro #" + std::to_string(sujeto.id);
    return std::string();
}

/**
 * @brief Etiqueta corta de un hecho, en el idioma activo.
 *
 * Solo se traducen los codigos que el catalogo conoce.  Para el resto se manda
 * el codigo del vocabulario tal cual: es estable y se puede buscar, que es mas
 * util que una frase inventada aqui.
 *
 * @param p Lo que se afirma.
 * @return Texto listo para ensenar junto al codigo.
 */
std::string etiqueta_del_hecho(const analysis::asa::Claim &p) {
    const std::string codigo = p.code ? p.code : "";
    const std::string a = std::to_string(p.a);
    const std::string b = std::to_string(p.b);
    const std::string detalle = p.detail ? p.detail : "";
    if (codigo == "range.bounded") return vx::diag::format("VX9150", {a, b});
    if (codigo == "range.constant") return vx::diag::format("VX9151", {a});
    if (codigo == "range.unreachable") return vx::diag::format("VX9152");
    if (codigo == "layout.section_alignment")
        return vx::diag::format("VX9153", {a, detalle});
    if (codigo == "loop.header") return vx::diag::format("VX9154", {a});
    if (codigo == "memory.points_to")
        return vx::diag::format("VX9155", {detalle.empty() ? a : detalle});
    // Sin entrada en el catalogo: el codigo, que es vocabulario estable.
    if (detalle.empty()) return codigo;
    return codigo + " " + detalle;
}

} // namespace

nlohmann::json Inspector::targets() {
    // Cada arquitectura con su nombre para el usuario, su clave para las
    // peticiones y la ISA con la que buscarla en la base de instrucciones.
    struct Entrada {
        const char *id;   ///< lo que se manda en `arch`.
        const char *name; ///< como se lee.
        vx::instr_db::Isa isa;
        aot::AotArch arch;
    };
    static const Entrada kArquitecturas[] = {
        {"x86-64", "x86-64", vx::instr_db::Isa::X86, aot::AotArch::X86_64},
        {"x86-32", "x86-32 (modo protegido)", vx::instr_db::Isa::X86,
         aot::AotArch::X86_32},
        {"aarch64", "AArch64", vx::instr_db::Isa::ARM64, aot::AotArch::ARM64},
        {"arm32", "ARM de 32 bits", vx::instr_db::Isa::ARM32,
         aot::AotArch::ARM32},
        {"riscv64", "RISC-V 64", vx::instr_db::Isa::RISCV,
         aot::AotArch::RISCV64},
    };

    nlohmann::json arquitecturas = nlohmann::json::array();
    for (const Entrada &e : kArquitecturas) {
        nlohmann::json ja;
        ja["id"] = e.id;
        ja["name"] = e.name;
        // Si hay generador de codigo o solo se puede mirar la base: decirlo
        // evita ofrecer una vista que despues no puede responder.
        ja["codegen"] = (aot::make_native_backend(e.arch) != nullptr);

        nlohmann::json micros = nlohmann::json::array();
        const uint32_t nm = vx::instr_db::microarch_count(e.isa);
        for (uint32_t i = 0; i < nm; ++i) {
            const char *nombre = vx::instr_db::microarch_name(e.isa, i);
            if (nombre != nullptr && *nombre != '\0') micros.push_back(nombre);
        }
        ja["microarchs"] = std::move(micros);

        nlohmann::json cpus = nlohmann::json::array();
        const uint32_t nc = vx::instr_db::cpu_count(e.isa);
        for (uint32_t i = 0; i < nc; ++i) {
            const char *nombre = vx::instr_db::cpu_name(e.isa, i);
            if (nombre != nullptr && *nombre != '\0') cpus.push_back(nombre);
        }
        ja["cpus"] = std::move(cpus);
        arquitecturas.push_back(std::move(ja));
    }

    nlohmann::json out;
    out["architectures"] = std::move(arquitecturas);
    out["floatIsas"] =
        nlohmann::json::array({"sse2", "avx", "avx512", "x87", "auto"});
    out["optLevels"] = nlohmann::json::array({0, 1, 2, 3});
    return out;
}

/**
 * @brief Deja solo el ENSAMBLADOR de una linea que ademas lleva sintaxis Vesta.
 *
 * Un bloque se abre desde Vesta (@c asm @c volatile @c {, @c bytes @c nombre @c
 * {) y se puede escribir entero en una linea (@c asm @c { @c mov @c rax, @c
 * gs:[0x60] @c };).  Preguntando por el texto crudo, el mnemonico salia "asm" y
 * la instruccion de verdad no se miraba nunca.
 *
 * Solo se corta cuando lo que precede a la llave es la palabra que abre el
 * bloque: en el ensamblador tambien hay llaves -- las mascaras de AVX-512, @c
 * vaddpd @c zmm0{k1}, @c zmm1, @c zmm2 --, y ahi no hay nada que quitar.
 *
 * @param linea Linea del fuente.
 * @return El ensamblador que contenga, o vacio si no contiene ninguno.
 */
static std::string asm_text_of_line(const std::string &linea) {
    const size_t abre = linea.find('{');
    if (abre == std::string::npos) {
        /* La llave que CIERRA el bloque tambien es Vesta, y sola en su linea se
         * tomaba por un mnemonico. */
        const size_t cierra = linea.find('}');
        return cierra == std::string::npos ? linea : linea.substr(0, cierra);
    }
    const std::string antes = linea.substr(0, abre);
    auto palabra = [&antes](const char *w) {
        const size_t n = std::strlen(w);
        size_t p = antes.find(w);
        while (p != std::string::npos) {
            const bool izq =
                (p == 0) || !std::isalnum((unsigned char)antes[p - 1]);
            const size_t fin = p + n;
            const bool der = (fin >= antes.size()) ||
                             !std::isalnum((unsigned char)antes[fin]);
            if (izq && der) return true;
            p = antes.find(w, p + 1);
        }
        return false;
    };
    if (!palabra("asm") && !palabra("bytes")) return linea;
    std::string dentro = linea.substr(abre + 1);
    const size_t cierra = dentro.find('}');
    if (cierra != std::string::npos) dentro.resize(cierra);
    return dentro;
}

/**
 * @brief Localiza el bloque de ensamblador que contiene @p linea.
 *
 * Se cuenta hacia atras hasta la llave que abre, y hacia delante hasta la que
 * cierra.  Sirve tanto para @c asm @c { como para @c bytes @c nombre @c {, que
 * son las dos formas de escribir uno.
 *
 * @param docs   Almacen de documentos.
 * @param uri    Documento.
 * @param linea  Linea de dentro, contando desde uno.
 * @param inicio Salida: primera linea del cuerpo (desde uno).
 * @param fin    Salida: ultima linea del cuerpo (desde uno).
 * @return true si esa linea cae dentro de un bloque.
 */
static bool localizar_bloque_asm(DocumentStore &docs, const std::string &uri,
                                 uint32_t linea, uint32_t &inicio,
                                 uint32_t &fin) {
    if (linea == 0) return false;
    auto sin_comentario = [](std::string s) {
        const size_t pc = s.find(';');
        const size_t pb = s.find("//");
        size_t corte = std::string::npos;
        if (pc != std::string::npos) corte = pc;
        if (pb != std::string::npos &&
            (corte == std::string::npos || pb < corte))
            corte = pb;
        if (corte != std::string::npos) s.resize(corte);
        return s;
    };
    auto abre_bloque = [](const std::string &s) {
        // Lo que precede a la llave dice si el bloque es de ensamblador.
        const size_t llave = s.find('{');
        if (llave == std::string::npos) return false;
        const std::string antes = s.substr(0, llave);
        return antes.find("asm") != std::string::npos ||
               antes.find("bytes") != std::string::npos;
    };

    // Hacia atras: la llave sin cerrar que nos contiene.
    int profundidad = 0;
    uint32_t apertura = 0;
    for (uint32_t i = linea; i >= 1; --i) {
        const std::string s = sin_comentario(docs.line(uri, i - 1));
        for (size_t c = s.size(); c > 0; --c) {
            const char ch = s[c - 1];
            if (ch == '}') {
                ++profundidad;
            } else if (ch == '{') {
                if (profundidad == 0) {
                    if (!abre_bloque(s)) return false;
                    apertura = i;
                    break;
                }
                --profundidad;
            }
        }
        if (apertura != 0) break;
        if (i == 1) return false;
    }
    if (apertura == 0) return false;

    // Hacia delante: la llave que la cierra.
    profundidad = 0;
    uint32_t cierre = 0;
    for (uint32_t i = apertura;; ++i) {
        const std::string s = sin_comentario(docs.line(uri, i - 1));
        if (s.empty() && i > apertura + 4096) break; // fin del documento
        bool salir = false;
        for (size_t c = 0; c < s.size(); ++c) {
            if (s[c] == '{') {
                ++profundidad;
            } else if (s[c] == '}') {
                --profundidad;
                if (profundidad == 0) {
                    cierre = i;
                    salir = true;
                    break;
                }
            }
        }
        if (salir) break;
        if (i > apertura + 4096) break; // acotado: un bloque no es infinito
    }
    if (cierre == 0) return false;

    /* El cuerpo va ENTRE las llaves.  Si el bloque se escribio en una sola
     * linea, empieza y acaba en ella. */
    inicio = apertura;
    fin = cierre;
    return true;
}

nlohmann::json Inspector::asm_block(const std::string &uri, uint32_t line,
                                    const std::string &cpu,
                                    const std::string &arch) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    uint32_t inicio = 0, fin = 0;
    if (!localizar_bloque_asm(docs_, uri, line, inicio, fin))
        return {{"found", false}};

    /* El cuerpo: cada linea, quitando la sintaxis Vesta que la envuelve.  Se
     * conserva el numero de linea real de cada una, que es lo que permite
     * llevar del panel al codigo. */
    std::vector<std::pair<uint32_t, std::string>> cuerpo;
    for (uint32_t i = inicio; i <= fin; ++i) {
        std::string t = asm_text_of_line(docs_.line(uri, i - 1));
        const size_t a = t.find_first_not_of(" \t");
        if (a == std::string::npos) continue;
        t = t.substr(a);
        while (!t.empty() && (t.back() == ' ' || t.back() == '\t'))
            t.pop_back();
        if (t.empty()) continue;
        cuerpo.emplace_back(i, t);
    }
    if (cuerpo.empty()) return {{"found", false}};

    std::string texto;
    for (const auto &l : cuerpo) {
        texto += l.second;
        texto.push_back('\n');
    }

    const vx::instr_db::Isa isa =
        vx::isa_of_arch(arch.empty() ? std::string("x86-64") : arch);
    const vx::AsmCfg cfg = vx::build_asm_cfg(isa, texto);

    int32_t ua = cpu.empty() ? -1 : vx::instr_db::microarch_by_name(isa, cpu);
    if (ua < 0 && vx::instr_db::microarch_count(isa) > 0) ua = 0;
    const uint32_t ua_id = static_cast<uint32_t>(ua < 0 ? 0 : ua);

    /* De etiqueta a instruccion, para poder decir a DoNDE salta cada salto en
     * indices y no en nombres: el nombre obliga a quien dibuja a resolverlo
     * otra vez, y eso es tener el mismo criterio en dos sitios. */
    std::unordered_map<std::string, uint32_t> por_etiqueta;
    for (uint32_t i = 0; i < cfg.insns.size(); ++i)
        for (const std::string &et : cfg.insns[i].labels)
            por_etiqueta.emplace(et, i);

    auto nombre_term = [](vx::AsmTerm t) {
        switch (t) {
        case vx::AsmTerm::UncondJump: return "salto";
        case vx::AsmTerm::CondBranch: return "rama";
        case vx::AsmTerm::Call: return "llamada";
        case vx::AsmTerm::Ret: return "retorno";
        case vx::AsmTerm::Indirect: return "indirecto";
        case vx::AsmTerm::Unknown: return "sin clasificar";
        default: return "sigue";
        }
    };

    nlohmann::json instrucciones = nlohmann::json::array();
    for (uint32_t i = 0; i < cfg.insns.size(); ++i) {
        const vx::AsmInsn &in = cfg.insns[i];
        if (in.sintetica) continue; // la salida no la escribio nadie
        nlohmann::json j;
        j["index"] = i;
        j["text"] = in.text;
        // `line_no` cuenta desde uno sobre las lineas del cuerpo.
        j["line"] = (in.line_no >= 1 && in.line_no <= cuerpo.size())
                        ? cuerpo[in.line_no - 1].first
                        : 0u;
        j["labels"] = in.labels;
        j["flow"] = nombre_term(in.term);
        j["target"] = in.target;
        auto it = por_etiqueta.find(in.target);
        j["targetIndex"] =
            it == por_etiqueta.end() ? -1 : static_cast<int>(it->second);
        /* Salta a algo que no esta en el bloque, pero que existe: una funcion
         * del modulo.  Sin decirlo, la linea se quedaba sin flecha y sin
         * explicacion, como si el salto no fuera a ninguna parte. */
        j["exitsTo"] = (it == por_etiqueta.end() && !in.target.empty() &&
                        vx::asm_is_external_symbol(in.target))
                           ? in.target
                           : std::string();

        // Lo que la base sabe de ella, y lo que cuesta aqui.
        const vx::instr_db::AsmInsnSem sem =
            vx::instr_db::asm_insn_sem(isa, in.text, ua_id);
        j["known"] = sem.form_id >= 0;
        if (sem.form_id >= 0) {
            const char *clase = vx::instr_db::iclass_name(isa, sem.form_id);
            if (clase != nullptr) j["iclass"] = clase;
            const vx::instr_db::AsmCost c =
                vx::instr_db::cost(isa, sem.form_id, ua_id);
            if (c.found) {
                nlohmann::json jc;
                jc["latency"] = c.latency;
                jc["reciprocalThroughput"] = c.recip_tp;
                jc["uops"] = c.uops;
                j["cost"] = std::move(jc);
            }
        }
        j["modeled"] = sem.modeled;
        j["barrier"] = sem.barrier;
        j["reads"] = sem.reads;
        j["writes"] = sem.writes;
        j["readsMemory"] = sem.reads_mem;
        j["writesMemory"] = sem.writes_mem;
        std::vector<std::string> lee, escribe;
        if (sem.form_id >= 0 &&
            vx::instr_db::flag_names_of(isa, sem.form_id, lee, escribe)) {
            j["flagsRead"] = lee;
            j["flagsWritten"] = escribe;
        }
        instrucciones.push_back(std::move(j));
    }

    nlohmann::json out;
    out["found"] = true;
    out["isa"] = vx::instr_db::isa_name(isa);
    out["microarch"] = vx::instr_db::microarch_name(isa, ua_id);
    out["firstLine"] = inicio;
    out["lastLine"] = fin;
    out["instructions"] = std::move(instrucciones);
    /* Donde el grafo deja de valer.  Un salto indirecto o una etiqueta que no
     * esta no son un detalle: a partir de ahi las flechas no cuentan todo el
     * flujo, y ensenarlas sin decirlo seria afirmar de mas. */
    out["hasIndirect"] = cfg.has_indirect;
    out["hasUnresolved"] = cfg.has_unresolved_target;
    out["hasExternal"] = cfg.has_external_target;
    out["unknownTerminators"] = cfg.unknown_terminators;
    return out;
}

nlohmann::json Inspector::asm_flow(const std::string &uri,
                                   const std::string &arch) {
    nlohmann::json bloques = nlohmann::json::array();
    if (!docs_.has(uri)) return {{"blocks", std::move(bloques)}};

    /* Se recorre el documento buscando aperturas de bloque.  Localizar cada uno
     * se hace con el MISMO codigo que usa la vista de un bloque suelto: dos
     * ideas de donde empieza y acaba un bloque acabarian discrepando, y se
     * notaria como flechas que aparecen en un sitio y no en el otro. */
    const uint32_t total = docs_.line_count(uri);
    for (uint32_t linea = 1; linea <= total;) {
        uint32_t ini = 0, fin = 0;
        if (localizar_bloque_asm(docs_, uri, linea, ini, fin) && ini == linea) {
            nlohmann::json b = asm_block(uri, linea + (fin > linea ? 1 : 0),
                                         std::string(), arch);
            if (b.value("found", false)) {
                nlohmann::json j;
                j["firstLine"] = b["firstLine"];
                j["lastLine"] = b["lastLine"];
                j["hasIndirect"] = b["hasIndirect"];
                j["hasUnresolved"] = b["hasUnresolved"];
                j["hasExternal"] = b["hasExternal"];
                /* Solo lo que hace falta para dibujar: de que linea a que
                 * linea, y de que clase es el salto.  Lo demas lo pide quien
                 * quiera el detalle. */
                nlohmann::json saltos = nlohmann::json::array();
                /* Las lineas por las que el flujo SALE del bloque hacia una
                 * funcion del modulo.  No son un salto que dibujar entre dos
                 * lineas -- el destino no esta aqui -- pero tampoco son nada:
                 * dejarlas mudas es lo que hacia parecer que un bloque entero
                 * no tenia flujo. */
                nlohmann::json salidas = nlohmann::json::array();
                const auto &insns = b["instructions"];
                for (const auto &in : insns) {
                    const std::string fuera =
                        in.value("exitsTo", std::string());
                    if (!fuera.empty() && in.value("line", 0u) != 0) {
                        nlohmann::json e;
                        e["line"] = in.value("line", 0u);
                        e["symbol"] = fuera;
                        e["flow"] = in.value("flow", std::string());
                        salidas.push_back(std::move(e));
                    }
                    const int destino = in.value("targetIndex", -1);
                    if (destino < 0) continue;
                    if (destino >= static_cast<int>(insns.size())) continue;
                    nlohmann::json s;
                    s["fromLine"] = in.value("line", 0u);
                    s["toLine"] =
                        insns[static_cast<size_t>(destino)].value("line", 0u);
                    s["flow"] = in.value("flow", std::string());
                    s["target"] = in.value("target", std::string());
                    if (s["fromLine"] != 0 && s["toLine"] != 0)
                        saltos.push_back(std::move(s));
                }
                j["jumps"] = std::move(saltos);
                j["exits"] = std::move(salidas);
                bloques.push_back(std::move(j));
            }
            linea = fin + 1;
            continue;
        }
        ++linea;
    }

    nlohmann::json out;
    out["blocks"] = std::move(bloques);
    return out;
}

nlohmann::json Inspector::instruction(const std::string &uri, uint32_t line,
                                      const std::string &cpu,
                                      const std::string &arch) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    const auto texto_doc_ref = docs_.text(uri);
    const std::string &texto_doc = *texto_doc_ref;
    // El almacen devuelve vacio si la linea no existe, asi que basta con
    // descartar el cero (las lineas se cuentan desde uno hacia fuera).
    const std::string linea_texto =
        line >= 1 ? asm_text_of_line(docs_.line(uri, line - 1)) : std::string();

    /* Lo primero es que le paso a esa instruccion, porque cambia lo que se
     * puede decir de ella.  El elevado convierte el subconjunto COMPUTACIONAL
     * del ensamblador a operaciones del IR tipadas -- ahi deja de haber una
     * instruccion que cronometrar y pasa a haber codigo que el optimizador
     * mueve --; lo demas queda como una micro que LLEVA su identidad en la
     * base (ISA y forma) ya resuelta.  Decir en cual de los dos casos estamos
     * es informacion, no un detalle de implementacion. */
    std::string elevado = "ninguno";
    std::vector<std::string> ops_ir;
    /* A que ISA se pregunta.  Si el compilador dejo micro, la lleva resuelta;
     * si no, la dice la arquitectura del bloque, que es la misma conversion que
     * usa el analisis de ensamblador.  Suponer x86 dejaba a un bloque arm
     * preguntando por instrucciones que no son las suyas. */
    vx::instr_db::Isa isa =
        vx::isa_of_arch(arch.empty() ? std::string("x86-64") : arch);
    int32_t form_id = -1;
    uint8_t eff_cache = 0;

    const auto an_ref = engine_.analyze_document(uri, texto_doc);
    const DocAnalysis &an = *an_ref;
    ir::IrModule mod;
    if (parse_post_opt_module(an.result, mod)) {
        for (const auto &fn : mod.functions) {
            for (const auto &b : fn.blocks) {
                for (const auto &in : b.instrs) {
                    if (in.source_line != line) continue;
                    if (in.op == ir::IrOp::ASM_MICRO) {
                        const size_t idx = static_cast<size_t>(in.imm);
                        if (idx < fn.asm_micros.size()) {
                            const ir::AsmMicro &m = fn.asm_micros[idx];
                            isa = static_cast<vx::instr_db::Isa>(m.isa);
                            form_id = static_cast<int32_t>(m.form_id);
                            eff_cache = m.eff;
                            elevado = "micro";
                        }
                    } else if (elevado == "ninguno") {
                        elevado = "ir";
                        ops_ir.push_back(ir::ir_op_name(in.op));
                    }
                }
            }
            if (elevado == "micro") break;
        }
    }

    /* Si el compilador no dejo micro para esa linea -- porque la elevo a
     * operaciones del IR, o porque el bloque se pidio opaco -- se le pregunta a
     * la base por el texto.  Se dice de donde salio cada cosa: lo resuelto por
     * el compilador y lo resuelto por texto no valen lo mismo. */
    if (form_id < 0 && !linea_texto.empty()) {
        form_id = vx::instr_db::match_asm_line(isa, linea_texto);
    }
    /* Una linea que no lleva mnemonico -- etiqueta, comentario, vacia -- no es
     * una instruccion y no tiene ficha.  Una que SI lo lleva y la base no
     * reconoce tambien se responde, diciendolo: es la que mas conviene ver,
     * porque el compilador la da por opaca y deja de mover nada a su
     * alrededor. */
    if (!vx::instr_db::has_mnemonic(linea_texto)) return {{"found", false}};

    // La microarquitectura decide el coste.  Si no se pide ninguna, se usa la
    // primera que tenga la base y se DICE cual, porque un numero de latencia
    // sin decir de que maquina no significa nada.
    int32_t ua = cpu.empty() ? -1 : vx::instr_db::microarch_by_name(isa, cpu);
    if (ua < 0 && vx::instr_db::microarch_count(isa) > 0) ua = 0;
    const uint32_t ua_id = static_cast<uint32_t>(ua < 0 ? 0 : ua);

    // La vista semantica del planificador, para los efectos con nombre.
    const vx::instr_db::AsmInsnSem sem =
        linea_texto.empty()
            ? vx::instr_db::AsmInsnSem{}
            : vx::instr_db::asm_insn_sem(isa, linea_texto, ua_id);

    nlohmann::json out;
    out["found"] = true;
    /* Si la base la conoce o no, dicho aparte de si la linea es una
     * instruccion: sin ese dato, "no se sabe" y "no hay nada que saber" se ven
     * igual desde fuera. */
    out["known"] = (form_id >= 0);
    if (form_id < 0) {
        out["unknownReason"] =
            vx::diag::format("VX9156", {vx::instr_db::isa_name(isa)});
    }
    out["isa"] = vx::instr_db::isa_name(isa);
    out["microarch"] = vx::instr_db::microarch_name(isa, ua_id);
    // Que hizo el compilador con ella, y de donde sale lo que se cuenta.
    out["lifted"] = elevado;
    out["resolvedBy"] = (elevado == "micro") ? "compilador" : "texto";
    if (!ops_ir.empty()) out["irOps"] = ops_ir;
    out["modeled"] = sem.modeled;
    // Una barrera no se puede cruzar: es lo primero que hay que saber al mover
    // codigo alrededor de ella.  Cuando viene de la micro, el compilador ya lo
    // dejo apuntado en su cache de efectos.
    out["barrier"] = sem.barrier || (eff_cache & 0x08) != 0;
    if (eff_cache != 0) {
        out["touchesMemory"] = (eff_cache & 0x01) != 0;
        out["isCall"] = (eff_cache & 0x10) != 0;
    }
    if (form_id >= 0) {
        const char *clase = vx::instr_db::iclass_name(isa, form_id);
        const char *ext = vx::instr_db::ext_of(isa, form_id);
        if (clase != nullptr) out["iclass"] = clase;
        if (ext != nullptr) out["extension"] = ext;
    }

    out["reads"] = sem.reads;
    out["writes"] = sem.writes;
    out["readsMemory"] = sem.reads_mem;
    out["writesMemory"] = sem.writes_mem;
    out["readsFlags"] = sem.reads_flags;
    out["writesFlags"] = sem.writes_flags;
    out["readsState"] = sem.reads_state;
    out["writesState"] = sem.writes_state;

    // Que banderas, por nombre.  Los booleanos de arriba dicen si toca alguna;
    // esto dice cuales, que es lo que evita estorbar de mas.
    if (form_id >= 0) {
        std::vector<std::string> lee, escribe;
        if (vx::instr_db::flag_names_of(isa, form_id, lee, escribe)) {
            out["flagsRead"] = lee;
            out["flagsWritten"] = escribe;
        }
    }

    if (sem.form_id >= 0) {
        const vx::instr_db::AsmCost c =
            vx::instr_db::cost(isa, sem.form_id, ua_id);
        nlohmann::json jc;
        // found=false significa que ESA microarquitectura no cronometra esta
        // forma; no que la instruccion no exista.
        jc["timed"] = c.found;
        if (c.found) {
            jc["latency"] = c.latency;
            jc["reciprocalThroughput"] = c.recip_tp;
            jc["uops"] = c.uops;
            jc["microcoded"] = c.microcoded;
            jc["macroFusible"] = c.macro_fusible;
            if (c.div_cycles >= 0.0f) jc["divCycles"] = c.div_cycles;
            nlohmann::json puertos = nlohmann::json::array();
            for (uint8_t i = 0; i < c.ports_count; ++i) {
                nlohmann::json jp;
                jp["port"] = c.ports[i].port;
                jp["uops"] = c.ports[i].uops;
                if (c.port_names != nullptr)
                    jp["name"] = c.port_names[c.ports[i].port];
                puertos.push_back(std::move(jp));
            }
            jc["ports"] = std::move(puertos);
        }
        out["cost"] = std::move(jc);
    }
    return out;
}

nlohmann::json Inspector::asa_facts(const std::string &uri) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;
    const auto an_ref = engine_.analyze_document(uri, text);
    const DocAnalysis &an = *an_ref;
    ir::IrModule mod;
    if (!parse_post_opt_module(an.result, mod))
        return {{"error", "el modulo no produjo IR (revisa los diagnosticos)"}};

    analyze::register_asm_producer();
    analysis::asa::FactStore almacen;
    const std::vector<analysis::asa::ProductionSummary> resumenes =
        /* POST-optimizacion, y lo dice el propio `parse_post_opt_module` de
         * arriba: esta vista ensena lo que se sabe del codigo que de verdad se
         * va a emitir. */
        analysis::asa::produce(mod, almacen, {},
                               analysis::asa::kStagePostOpt);

    nlohmann::json hechos = nlohmann::json::array();
    for (size_t i = 0; i < almacen.size(); ++i) {
        const analysis::asa::Fact &f = almacen.at(i);
        nlohmann::json j;
        j["line"] = linea_del_sujeto(mod, f.about);
        j["function"] = f.about.function ? f.about.function : "";
        j["functionDisplay"] =
            vx::demangle_symbol(f.about.function ? f.about.function : "");
        j["subject"] = analysis::asa::subject_kind_name(f.about.kind);
        // De QUE habla, no solo de que CLASE de cosa: el identificador y la
        // operacion que lo define.  Sin esto, ocho hechos sobre ocho valores
        // distintos de la misma linea son ocho filas identicas que dicen
        // "valor" y no se pueden distinguir.
        j["subjectId"] = f.about.id;
        j["subjectText"] = texto_del_sujeto(mod, f.about);
        /* Y lo mismo dicho en CoDIGO.
         *
         * `%12 = add %7, 40` identifica sin lugar a dudas, y no sirve de nada
         * si no se tiene el IR delante -- que es casi siempre --.  La linea del
         * fuente es de lo que uno esta hablando cuando programa, asi que va
         * como lo principal y la operacion del IR queda para quien la quiera.
         */
        {
            const uint32_t linea = j["line"].get<uint32_t>();
            std::string src = linea >= 1 ? docs_.line(uri, linea - 1) : "";
            const size_t ini = src.find_first_not_of(" \t");
            if (ini == std::string::npos)
                src.clear();
            else
                src = src.substr(ini);
            // Una linea muy larga no cabe en una celda y tampoco hace falta
            // entera para reconocerla.
            if (src.size() > 120) src = src.substr(0, 117) + "...";
            j["sourceText"] = src;
        }
        j["domain"] = f.what.domain ? f.what.domain : "";
        j["code"] = f.what.code ? f.what.code : "";
        j["a"] = f.what.a;
        j["b"] = f.what.b;
        j["detail"] = f.what.detail ? f.what.detail : "";
        j["label"] = etiqueta_del_hecho(f.what);
        j["certainty"] = analysis::asa::certainty_name(f.seal.certainty);
        j["source"] = analysis::asa::source_name(f.seal.origin.source);
        // El ambito importa: un hecho puede valer solo para una arquitectura o
        // un backend, y ensenarlo sin decirlo seria mentir por omision.
        j["isa"] = f.scope.isa ? f.scope.isa : "";
        j["os"] = f.scope.os ? f.scope.os : "";
        j["backend"] = f.scope.backend ? f.scope.backend : "";

        /* COMO se llego a el.  Es la mitad que faltaba: sin la regla y sin los
         * hechos de los que se sigue, un hecho es una afirmacion que hay que
         * creerse.  Con ellos se puede recorrer la derivacion hacia atras --
         * que es lo que el modelo llama "todo veredicto lleva su prueba" y lo
         * que el editor estaba tirando --. */
        j["rule"] = f.proof.rule ? f.proof.rule : "";
        nlohmann::json de = nlohmann::json::array();
        for (const analysis::asa::FactId id : f.proof.from)
            de.push_back(id);
        j["from"] = std::move(de);
        /* Y quien lo emitio, con el sitio exacto que miro: el numero de valor o
         * de bloque del que salio, que es lo que permite cruzarlo con el IR. */
        j["producer"] = f.seal.origin.producer ? f.seal.origin.producer : "";
        j["site"] = f.seal.origin.site;
        /* En que se apoya, por analisis.  Grueso, pero dice si un hecho es de
         * cosecha propia o depende de lo que otro dedujo antes. */
        nlohmann::json apoyos = nlohmann::json::array();
        for (const char *p : f.seal.support.on)
            if (p != nullptr && *p != '\0') apoyos.push_back(p);
        j["restsOn"] = std::move(apoyos);
        hechos.push_back(std::move(j));
    }

    /* Que MIRA cada analisis, en una frase.
     *
     * Un hecho suelto -- "rango 0..65535" -- es cierto y no dice para que
     * sirve saberlo.  Puesto debajo de "entre que valores se puede mover, y
     * que descarta eso", ya se entiende que es y por que esta ahi. */
    auto proposito = [](const std::string &dominio) -> std::string {
        if (dominio == "asa.ranges") return vx::diag::format("VX9160", {});
        if (dominio == "asa.memory") return vx::diag::format("VX9161", {});
        if (dominio == "asa.structure") return vx::diag::format("VX9162", {});
        if (dominio == "asa.boundary") return vx::diag::format("VX9163", {});
        if (dominio == "asa.loops") return vx::diag::format("VX9164", {});
        if (dominio == "asa.asm") return vx::diag::format("VX9165", {});
        if (dominio == "asa.asm_flow") return vx::diag::format("VX9166", {});
        if (dominio == "asa.layout") return vx::diag::format("VX9167", {});
        if (dominio == "asa.value_shape") return vx::diag::format("VX9168", {});
        return std::string();
    };

    nlohmann::json dominios = nlohmann::json::array();
    for (const auto &r : resumenes) {
        nlohmann::json j;
        j["domain"] = r.domain ? r.domain : "";
        j["purpose"] = proposito(r.domain ? r.domain : "");
        j["facts"] = r.facts;
        j["looked"] = r.looked_at;
        j["silent"] = r.silent;
        j["micros"] = static_cast<int64_t>(r.micros);
        nlohmann::json motivos = nlohmann::json::array();
        for (const auto &m : r.reasons) {
            nlohmann::json jm;
            jm["code"] = m.code ? m.code : "";
            jm["times"] = m.times;
            /* La CLASE del no saber, que es lo que decide la accion: dos
             * codigos distintos de la misma clase se arreglan igual, y quien
             * mira el editor no tiene por que conocer el dominio. */
            jm["reason"] = analysis::asa::unknown_reason_name(m.reason);
            motivos.push_back(std::move(jm));
        }
        j["unknown"] = std::move(motivos);
        dominios.push_back(std::move(j));
    }

    nlohmann::json out;
    out["facts"] = std::move(hechos);
    out["domains"] = std::move(dominios);
    return out;
}

bool Inspector::view_cached(const std::string &key, std::string &out) const {
    std::lock_guard<std::mutex> guard(caches_);
    auto it = view_cache_.find(key);
    if (it == view_cache_.end()) return false;
    out = it->second;
    return true;
}

void Inspector::view_store(const std::string &key, std::string value) {
    std::lock_guard<std::mutex> guard(caches_);
    view_cache_[key] = std::move(value);
}

std::shared_ptr<const Inspector::AotBuild>
Inspector::aot_build(const std::string &uri, const std::string &text,
                     const std::string &target_key, int opt_level) {
    const std::string key =
        uri + "|" + std::to_string(fnv1a_hash(text)) + "|aot" + target_key;
    {
        std::lock_guard<std::mutex> guard(caches_);
        auto it = aot_cache_.find(key);
        if (it != aot_cache_.end()) return it->second;
    }

    vx::CompileOptions co;
    co.module_name = "main";
    // La semantica del modo nativo.  Es la que decide como baja cada
    // constructo, y por tanto la unica sobre la que tiene sentido preguntar si
    // el modo nativo puede con el.
    co.native_poo = true;
    // El nivel de optimizacion pedido, si se pidio alguno.  Ver el MISMO
    // codigo a dos niveles es como se ve que hizo el optimizador, que es media
    // pregunta de por que algo va como va.
    if (opt_level >= 0) co.opt_level = opt_level;

    // Por el mismo sitio que el resto de las vistas: como proyecto cuando el
    // fichero esta en disco, con el texto vivo por encima.
    const vx::CompileResult res = compile_document(uri, text, co);

    AotBuild build;
    const std::pair<size_t, size_t> diags = count_diags(res);
    build.errors = diags.first;
    build.warnings = diags.second;
    build.ir_bytes = res.ir_module_cache_bytes;
    /* Dos peticiones pueden haber compilado lo mismo a la vez -- se prefiere
     * eso a hacerlas esperar --, asi que la que llegue segunda se queda con la
     * que ya esta puesta: las dos dicen lo mismo y asi solo hay un objeto. */
    auto hecho = std::make_shared<const AotBuild>(std::move(build));
    std::lock_guard<std::mutex> guard(caches_);
    auto ins = aot_cache_.emplace(key, std::move(hecho));
    return ins.first->second;
}

nlohmann::json Inspector::modes(const std::string &uri, const std::string &mode,
                                const std::string &tier) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;
    const bool all = mode.empty();
    nlohmann::json arr = nlohmann::json::array();

    // ---- interprete / VM (analisis siempre-activo) ----
    if (all || mode == "interp") {
        const auto an_ref = engine_.analyze_document(uri, text);
        const DocAnalysis &an = *an_ref;
        auto [err, warn] = count_diags(an.result);
        nlohmann::json m;
        m["mode"] = "interp";
        m["ok"] = !an.result.diagnostics.has_errors();
        m["errors"] = static_cast<uint64_t>(err);
        m["warnings"] = static_cast<uint64_t>(warn);
        m["note"] = "semantica de interprete/VM (runtime completo)";
        arr.push_back(std::move(m));
    }

    // ---- JIT (mismo IR que el interprete; compilabilidad por funcion) ----
    if (all || mode == "jit") {
        nlohmann::json m;
        m["mode"] = "jit";
        const auto an_ref = engine_.analyze_document(uri, text);
        const DocAnalysis &an = *an_ref;
        ir::IrModule mod;
        if (!parse_post_opt_module(an.result, mod)) {
            m["ok"] = false;
            m["note"] = "el modulo no produjo IR (revisa los diagnosticos)";
        } else {
            nlohmann::json compilable = nlohmann::json::array();
            nlohmann::json fallback = nlohmann::json::array();
            for (const auto &fn : mod.functions) {
                std::vector<uint8_t> bytes;
                try {
                    bytes = jit::vreg_compile_native(
                        fn, /*resolve_call=*/{}, /*ent=*/{},
                        /*resolve_native=*/{}, /*resolve_symbol=*/{},
                        /*relocs=*/nullptr, /*pic=*/true,
                        /*target_sysv=*/false, /*mode32=*/false,
                        jit::FloatIsa::SSE2, /*emit_line_map=*/false,
                        /*line_map=*/nullptr, /*asm_labels=*/nullptr);
                } catch (...) {
                    bytes.clear();
                }
                if (bytes.empty())
                    fallback.push_back(fn.name);
                else
                    compilable.push_back(fn.name);
            }
            m["ok"] = true;
            m["compilable_functions"] = std::move(compilable);
            m["fallback_functions"] = std::move(fallback);
            m["note"] =
                "JIT vreg; las funciones no compilables caen al interprete";
        }
        arr.push_back(std::move(m));
    }

    // ---- AOT nativo (recompila con POO nativa + compat al tier) ----
    if (all || mode == "aot") {
        nlohmann::json m;
        m["mode"] = "aot";
        const std::string t = tier.empty() ? std::string("bare") : tier;
        m["tier"] = t;
        // La compilacion con la semantica nativa, por el mismo sitio que la
        // usa `aot_compat`: si cada vista la hiciera por su cuenta acabarian
        // contestando cosas distintas sobre el mismo programa.
        const auto build_ref = aot_build(uri, text);
        const AotBuild &build = *build_ref;
        m["errors"] = static_cast<uint64_t>(build.errors);
        m["warnings"] = static_cast<uint64_t>(build.warnings);
        ir::IrModule mod;
        if (build.ir_bytes.empty() ||
            !ir::parse_ir_module_cache(build.ir_bytes, mod)) {
            m["ok"] = false;
            m["compatible"] = false;
            m["note"] = "el modulo no produjo IR en modo AOT";
        } else {
            aot::AotTarget atgt;
            atgt.tier = tier_from_str(t);
            aot::AotCompatReport report = aot::aot_analyze_module(mod, atgt);
            nlohmann::json issues = nlohmann::json::array();
            for (const auto &iss : report.issues) {
                nlohmann::json ji;
                ji["fn_name"] = iss.fn_name;
                ji["fn_display"] = vx::demangle_symbol(iss.fn_name);
                ji["source_line"] = iss.source_line;
                ji["op"] = ir::ir_op_name(iss.op);
                ji["reason"] = iss.reason;
                issues.push_back(std::move(ji));
            }
            nlohmann::json okfns = nlohmann::json::array();
            for (const auto &name : report.ok_functions)
                okfns.push_back(name);
            m["ok"] = (build.errors == 0);
            m["compatible"] = report.compatible;
            m["issues"] = std::move(issues);
            m["ok_functions"] = std::move(okfns);
            m["note"] =
                "compilacion nativa standalone (POO nativa, tier " + t + ")";
        }
        arr.push_back(std::move(m));
    }

    if (arr.empty())
        return {{"error", "modo invalido (use interp|jit|aot o vacio)"}};
    nlohmann::json out;
    out["modes"] = std::move(arr);
    return out;
}

nlohmann::json Inspector::macro_expand(const std::string &uri) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    // Las expectaciones de @Macro y las razones de skip se pueblan en la
    // compilacion normal: reutilizar el CompileResult cacheado por el motor.
    const auto an_ref = engine_.analyze_document(uri, *docs_.text(uri));
    const DocAnalysis &an = *an_ref;
    const vx::CompileResult &res = an.result;

    nlohmann::json expansions = nlohmann::json::array();
    for (const auto &e : res.macro_expectations) {
        nlohmann::json je;
        je["macro_name"] = e.macro_name;
        je["call_site_loc"] = e.src_loc;
        nlohmann::json jargs = nlohmann::json::array();
        for (uint64_t a : e.args)
            jargs.push_back(a);
        je["args"] = std::move(jargs);
        je["generated_code"] = e.expected_str;
        expansions.push_back(std::move(je));
    }

    nlohmann::json skipped = nlohmann::json::array();
    for (const auto &s : res.macro_skip_reasons) {
        nlohmann::json js;
        js["name"] = s.first;
        js["reason"] = s.second;
        skipped.push_back(std::move(js));
    }

    nlohmann::json out;
    out["expansions"] = std::move(expansions);
    out["skipped"] = std::move(skipped);
    return out;
}

nlohmann::json Inspector::comptime_values(const std::string &uri) {
    if (!docs_.has(uri)) return {{"error", "documento no abierto"}};
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;

    // El snapshot de valores comptime exige recompilar con el flag
    // dump_comptime_values (no se hace en el analyze por pulsacion).  Cachear
    // el JSON por (uri, hash) para no recompilar peticiones identicas.
    const uint64_t h = fnv1a_hash(text);
    const std::string key = uri + "|" + std::to_string(h) + "|comptime-values";
    std::string guardado;
    if (view_cached(key, guardado)) return nlohmann::json::parse(guardado);

    vx::CompileOptions opts;
    opts.module_name = "main";
    opts.dump_comptime_values = true;
    vx::CompileResult res = compile_document(uri, text, opts);

    nlohmann::json values = nlohmann::json::array();
    for (const auto &v : res.comptime_values) {
        nlohmann::json jv;
        jv["name"] = v.name;
        jv["scope"] = v.scope;
        jv["type_kind"] = v.type_kind;
        jv["value_str"] = v.value_str;
        // Ubicacion (1-based; 0 = sin ubicacion) y clase de builtin, para que
        // el cliente pueda mostrar el valor inline (ghost text) sobre la
        // expresion sizeof/kind/... en su linea.
        jv["line"] = v.loc.line;
        jv["column"] = v.loc.column;
        jv["builtin_kind"] = v.builtin_kind;
        values.push_back(std::move(jv));
    }

    nlohmann::json out;
    out["values"] = std::move(values);
    view_store(key, out.dump());
    return out;
}

} // namespace lsp
