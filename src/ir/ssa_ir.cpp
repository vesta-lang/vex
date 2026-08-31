/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file ssa_ir.cpp
 * @brief Implementacion del printer, parser y verificador de la SSA IR.
 *
 * Funciones implementadas:
 *   ir_type_name()   -- nombre de texto de IrType
 *   ir_type_parse()  -- parseo de nombre de tipo
 *   ir_op_name()     -- nombre de texto de IrOp
 *   ir_op_parse()    -- parseo de nombre de opcode
 *   IrFunction::new_value()
 *   IrFunction::new_block()
 *   IrFunction::append()
 *   IrModule::add_function()
 *   ir_print()       -- serializar modulo a texto
 *   ir_parse()       -- parsear texto a modulo
 *   ir_verify()      -- verificar forma SSA
 */

#include "util/fnv.h" // la semilla y el primo, en UN sitio
#include "ir/ssa_ir.h"

#include <sstream>
#include <ostream>
#include <cassert>
#include <cstring>
#include <algorithm>
#include <unordered_set>

namespace ir {

/* =====================================================================
 * Tabla de tipos
 * ===================================================================== */

/**
 * @brief Entrada de la tabla de nombres de tipos.
 */
struct TypeEntry {
    const char *name;
    IrType type;
};

static const TypeEntry TYPE_TABLE[] = {
    {"void", IrType::VOID},     {"i8", IrType::I8},     {"i16", IrType::I16},
    {"i32", IrType::I32},       {"i64", IrType::I64},   {"u8", IrType::U8},
    {"u16", IrType::U16},       {"u32", IrType::U32},   {"u64", IrType::U64},
    {"f32", IrType::F32},       {"f64", IrType::F64},   {"ptr", IrType::PTR},
    {"handle", IrType::HANDLE}, {"bool", IrType::BOOL}, {nullptr, IrType::VOID},
};

/**
 * @brief Devuelve el nombre de texto de un IrType.
 */
const char *ir_type_name(IrType t) {
    for (const TypeEntry *e = TYPE_TABLE; e->name; ++e)
        if (e->type == t) return e->name;
    return "?";
}

/**
 * @brief Parsea el nombre de un tipo de texto a IrType.
 */
bool ir_type_parse(const char *name, IrType &out) {
    for (const TypeEntry *e = TYPE_TABLE; e->name; ++e) {
        if (std::strcmp(name, e->name) == 0) {
            out = e->type;
            return true;
        }
    }
    return false;
}

/* =====================================================================
 * Tabla de opcodes
 * ===================================================================== */

/**
 * @brief Entrada de la tabla de nombres de opcodes.
 */
struct OpEntry {
    const char *name;
    IrOp op;
};

static const OpEntry OP_TABLE[] = {
    // constantes y movimiento
    {"const", IrOp::CONST},
    {"mov", IrOp::MOV},
    {"nop", IrOp::NOP},
    {"str_lit_addr", IrOp::STR_LIT_ADDR},
    // aritmetica entera
    {"add", IrOp::ADD},
    {"sub", IrOp::SUB},
    {"mul", IrOp::MUL},
    {"div", IrOp::DIV},
    {"mod", IrOp::MOD},
    {"neg", IrOp::NEG},
    // aritmetica flotante
    {"fadd", IrOp::FADD},
    {"fsub", IrOp::FSUB},
    {"fmul", IrOp::FMUL},
    {"fma", IrOp::FMA},
    {"fdiv", IrOp::FDIV},
    {"fneg", IrOp::FNEG},
    {"fabs", IrOp::FABS},
    {"fsqrt", IrOp::FSQRT},
    {"fmin", IrOp::FMIN},
    {"fmax", IrOp::FMAX},
    {"ffloor", IrOp::FFLOOR},
    {"fceil", IrOp::FCEIL},
    {"fround", IrOp::FROUND},
    {"ftrunc", IrOp::FTRUNC},
    // ops vectoriales fusionadas (auto-vectorizacion)
    {"vec_unop", IrOp::VEC_UNOP},
    {"vec_binop", IrOp::VEC_BINOP},
    {"vec_fma", IrOp::VEC_FMA},
    {"vec_acc_zero", IrOp::VEC_ACC_ZERO},
    {"vec_acc_add", IrOp::VEC_ACC_ADD},
    {"vec_acc_fma", IrOp::VEC_ACC_FMA},
    {"vec_acc_store", IrOp::VEC_ACC_STORE},
    {"vec_acc_combine", IrOp::VEC_ACC_COMBINE},
    {"vec_binop_s", IrOp::VEC_BINOP_S},
    {"vec_fma_s", IrOp::VEC_FMA_S},
    {"vec_bcast", IrOp::VEC_BCAST},
    // aritmetica entera extendida (Math-IR-promote wave 4)
    {"iabs", IrOp::IABS},
    {"imin", IrOp::IMIN},
    {"imax", IrOp::IMAX},
    {"iminu", IrOp::IMINU},
    {"imaxu", IrOp::IMAXU},
    {"ilog2", IrOp::ILOG2},
    {"select", IrOp::SELECT},
    // multiprecision: suma/resta que dejan acarreo, y su lectura
    {"addc", IrOp::ADDC},
    {"subb", IrOp::SUBB},
    {"carryof", IrOp::CARRYOF},
    // logica y desplazamientos
    {"and", IrOp::AND},
    {"or", IrOp::OR},
    {"xor", IrOp::XOR},
    {"not", IrOp::NOT},
    {"shl", IrOp::SHL},
    {"shr", IrOp::SHR},
    {"sar", IrOp::SAR},
    // bit ops extendidos (Math-IR-promote wave 4)
    {"clz", IrOp::CLZ},
    {"ctz", IrOp::CTZ},
    {"popcnt", IrOp::POPCNT},
    {"byteswap", IrOp::BYTESWAP},
    {"rotl", IrOp::ROTL},
    {"rotr", IrOp::ROTR},
    // comparaciones enteras
    {"cmp.eq", IrOp::CMP_EQ},
    {"cmp.ne", IrOp::CMP_NE},
    {"cmp.lt", IrOp::CMP_LT},
    {"cmp.gt", IrOp::CMP_GT},
    {"cmp.le", IrOp::CMP_LE},
    {"cmp.ge", IrOp::CMP_GE},
    {"cmp.ult", IrOp::CMP_ULT},
    {"cmp.ugt", IrOp::CMP_UGT},
    {"cmp.ule", IrOp::CMP_ULE},
    {"cmp.uge", IrOp::CMP_UGE},
    // comparaciones flotantes
    {"fcmp.eq", IrOp::FCMP_EQ},
    {"fcmp.ne", IrOp::FCMP_NE},
    {"fcmp.lt", IrOp::FCMP_LT},
    {"fcmp.gt", IrOp::FCMP_GT},
    {"fcmp.le", IrOp::FCMP_LE},
    {"fcmp.ge", IrOp::FCMP_GE},
    // conversiones
    {"cast", IrOp::CAST},
    {"zext", IrOp::ZEXT},
    {"sext", IrOp::SEXT},
    {"trunc", IrOp::TRUNC},
    {"itof", IrOp::ITOF},
    {"uitof", IrOp::UITOF},
    {"ftoi", IrOp::FTOI},
    {"ftoui", IrOp::FTOUI},
    {"f32tof64", IrOp::F32TOF64},
    {"f64tof32", IrOp::F64TOF32},
    {"bitcast", IrOp::BITCAST},
    // flujo de control
    {"br", IrOp::BR},
    {"br.cond", IrOp::BR_COND},
    {"ret", IrOp::RET},
    {"unreachable", IrOp::UNREACHABLE},
    // SSA
    {"phi", IrOp::PHI},
    // llamadas
    {"call", IrOp::CALL},
    {"callind", IrOp::CALLIND},
    {"tailcall", IrOp::TAILCALL},
    {"callvirt", IrOp::CALLVIRT},
    {"callm", IrOp::CALLM},
    {"callitf", IrOp::CALLITF},
    {"callclosure", IrOp::CALLCLOSURE},
    {"make_closure", IrOp::MAKE_CLOSURE},
    {"make_variant", IrOp::MAKE_VARIANT},
    {"match_variant", IrOp::MATCH_VARIANT},
    {"switch_dense", IrOp::SWITCH_DENSE},
    {"calln", IrOp::CALLN},
    // memoria
    {"alloca", IrOp::ALLOCA},
    {"load", IrOp::LOAD},
    {"store", IrOp::STORE},
    {"memcpy", IrOp::MEMCPY},
    {"memset", IrOp::MEMSET},
    {"raw_alloc", IrOp::RAW_ALLOC},
    {"raw_free", IrOp::RAW_FREE},
    {"gc_alloc", IrOp::GC_ALLOC},
    {"spawn_args", IrOp::SPAWN_ARGS},
    // OOP / GC
    {"newobj", IrOp::NEWOBJ},
    {"getfield", IrOp::GETFIELD},
    {"setfield", IrOp::SETFIELD},
    {"instanceof", IrOp::INSTANCEOF},
    {"checkcast", IrOp::CHECKCAST},
    {"isnull", IrOp::ISNULL},
    {"unwrap", IrOp::UNWRAP},
    {"specialize", IrOp::SPECIALIZE},
    {"gep", IrOp::GEP},
    {"gcwb_ir", IrOp::GCWB_IR},
    {"array_alloc", IrOp::ARRAY_ALLOC},
    {"array_len", IrOp::ARRAY_LEN},
    {"array_load", IrOp::ARRAY_LOAD},
    {"array_store", IrOp::ARRAY_STORE},
    {"gcderef_ir", IrOp::GCDEREF_IR},
    {"gc_deref_host", IrOp::GC_DEREF_HOST},
    {"rethrow", IrOp::RETHROW},
    {"shared_stat", IrOp::SHARED_STAT},
    {"read_vm_reg", IrOp::READ_VM_REG},
    {"rspawn_return", IrOp::RSPAWN_RETURN},
    {"smartptr_free", IrOp::SMARTPTR_FREE},
    {"reflect_count", IrOp::REFLECT_COUNT},
    {"reflect_at", IrOp::REFLECT_AT},
    {"mod_load", IrOp::MOD_LOAD},
    {"dlopen", IrOp::DLOPEN},
    {"dlsym", IrOp::DLSYM},
    // excepciones
    {"throw", IrOp::THROW},
    {"tryenter", IrOp::TRYENTER},
    {"tryleave", IrOp::TRYLEAVE},
    {"landingpad", IrOp::LANDINGPAD},
    // cadenas
    {"strmake", IrOp::STRMAKE},
    {"strlen", IrOp::STRLEN},
    {"strcat", IrOp::STRCAT},
    {"strcmp", IrOp::STRCMP},
    {"strslice", IrOp::STRSLICE},
    {"strflat", IrOp::STRFLAT},
    {"strhash", IrOp::STRHASH},
    {"strintern", IrOp::STRINTERN},
    {"strraw", IrOp::STRRAW},
    {"strconv", IrOp::STRCONV},
    {"strreserve", IrOp::STRRESERVE},
    {"strfinalize", IrOp::STRFINALIZE},
    // async
    {"future", IrOp::FUTURE},
    {"await", IrOp::AWAIT},
    {"fulfill", IrOp::FULFILL},
    {"reject", IrOp::REJECT},
    // distribucion
    {"msgsend", IrOp::MSGSEND},
    {"msgrecv", IrOp::MSGRECV},
    {"rspawn", IrOp::RSPAWN},
    // monitores
    {"monenter", IrOp::MONENTER},
    {"monexit", IrOp::MONEXIT},
    {"monwait", IrOp::MONWAIT},
    {"monnoti", IrOp::MONNOTI},
    {"monnota", IrOp::MONNOTA},
    // intrinsics VM
    {"getproc", IrOp::GETPROC},
    {"getvm", IrOp::GETVM},
    {"getmgr", IrOp::GETMGR},
    {"spawn", IrOp::SPAWN},
    {"spawnon", IrOp::SPAWN_ON},
    {"resume", IrOp::RESUME},
    {"yield", IrOp::YIELD},
    {"swapctx", IrOp::SWAPCTX},
    {"hlt", IrOp::HLT},
    {"getpid", IrOp::GETPID},
    {"getargc", IrOp::GETARGC},
    {"getarg", IrOp::GETARG},
    {"panic", IrOp::PANIC},
    // constante: direccion absoluta de un label resuelta por el linker
    {"label_addr", IrOp::LABEL_ADDR},
    // memoria extra (move-and-take, gcallocp, static fields, atomics)
    {"mvtake_ir", IrOp::MVTAKE_IR},
    {"gc_set_finalizer", IrOp::GC_SET_FINALIZER},
    {"gc_collect", IrOp::GC_COLLECT},
    {"gc_finalize_all", IrOp::GC_FINALIZE_ALL},
    {"gc_allocp", IrOp::GC_ALLOCP},
    {"getstatic", IrOp::GETSTATIC},
    {"setstatic", IrOp::SETSTATIC},
    {"atomic_ld_i64", IrOp::ATOMIC_LD},
    {"atomic_st_i64", IrOp::ATOMIC_ST},
    {"atomic_cas_i64", IrOp::ATOMIC_CAS},
    {"atomic_add_i64", IrOp::ATOMIC_ADD},
    // async fusion + string extra
    {"fulfill_hlt", IrOp::FULFILL_HLT},
    {"strgetbytes", IrOp::STRGETBYTES},
    // meta-OOP / reflexion /  Z extras
    {"gc_handle_for_ptr", IrOp::GC_HANDLE_FOR_PTR},
    {"gc_promote", IrOp::GC_PROMOTE},
    {"gc_demote", IrOp::GC_DEMOTE},
    {"findclass", IrOp::FINDCLASS},
    {"defclass", IrOp::DEFCLASS},
    {"deffield", IrOp::DEFFIELD},
    {"defmethod", IrOp::DEFMETHOD},
    {"addadvice", IrOp::ADDADVICE},
    {"findmethod", IrOp::FINDMETHOD},
    {"findfield", IrOp::FINDFIELD},
    {"setmethdbg", IrOp::SETMETHDBG},
    {"newobjs", IrOp::NEWOBJS},
    {"callsuper", IrOp::CALLSUPER},
    {"proceed", IrOp::PROCEED},
    // ensamblador incrustado
    {"asm_micro", IrOp::ASM_MICRO},
    {"inline_asm", IrOp::INLINE_ASM},
    {"raw_asm", IrOp::RAW_ASM},
    {nullptr, IrOp::NOP},
};

namespace {
/// Array PLANO nombre-por-opcode (IrOp cabe en un byte 0x00..0xFF): lookup O(1)
/// por indice en vez de recorrer @c OP_TABLE.  Se construye una sola vez desde
/// @c OP_TABLE; el constructor del static local es thread-safe (C++11).
struct OpNameTable {
    const char *name[256] = {nullptr};
    OpNameTable() {
        for (const OpEntry *e = OP_TABLE; e->name; ++e)
            name[(unsigned char)e->op] = e->name;
    }
};
} // namespace

/**
 * @brief Devuelve el nombre de texto de un IrOp (O(1), array indexado por
 * opcode).
 */
const char *ir_op_name(IrOp op) {
    static const OpNameTable t;
    const char *n = t.name[(unsigned char)op];
    return n ? n : "?";
}

/**
 * @brief Parsea el nombre de un opcode de texto a IrOp.
 */
bool ir_op_parse(const char *name, IrOp &out) {
    for (const OpEntry *e = OP_TABLE; e->name; ++e) {
        if (std::strcmp(name, e->name) == 0) {
            out = e->op;
            return true;
        }
    }
    return false;
}

/* =====================================================================
 * IrFunction: gestion de valores y bloques
 * ===================================================================== */

/**
 * @brief Crea un nuevo valor SSA en el pool de la funcion.
 */
IrValueId IrFunction::new_value(IrType type, const std::string &nm) {
    IrValue v;
    v.id = static_cast<IrValueId>(values.size());
    v.type = type;
    v.is_param = false;
    v.is_const = false;
    v.const_val = 0;
    v.name = nm.empty() ? ("%" + std::to_string(v.id)) : nm;
    values.push_back(std::move(v));
    return values.back().id;
}

/**
 * @brief Crea un nuevo bloque basico.
 *
 * Garantiza nombres unicos dentro de la funcion (necesario porque el
 * emisor IR los traduce a etiquetas .vel y los .vel exigen unicidad
 * por seccion).  Si el frontend pasa el mismo nombre logico para dos
 * bloques (caso tipico: dos while anidados que ambos se llaman
 * "while_header"), se anexa "_<id>" para distinguirlos.  Si pasa
 * vacio, se genera "bbN".
 */
IrBlockId IrFunction::new_block(const std::string &nm) {
    IrBlock b;
    b.id = static_cast<IrBlockId>(blocks.size());
    b.name = nm.empty() ? ("bb" + std::to_string(b.id))
                        : (nm + "_" + std::to_string(b.id));
    blocks.push_back(std::move(b));
    return blocks.back().id;
}

/**
 * @brief Anade una instruccion al bloque indicado.
 */
void IrFunction::append(IrBlockId block_id, IrInstr instr) {
    assert(block_id < static_cast<IrBlockId>(blocks.size()));
    blocks[block_id].instrs.push_back(std::move(instr));
}

/* =====================================================================
 * IrModule
 * ===================================================================== */

size_t IrModule::add_function(IrFunction fn) {
    size_t idx = functions.size();
    functions.push_back(std::move(fn));
    return idx;
}

/**
 * @brief Registra (con deduplicacion) un blob de bytes en static_data.
 *
 * La deduplicacion compara contenido completo; en programas con muchos
 * literales repetidos esto reduce el tamano del .vel emitido.
 * Coste O(N*M) en el peor caso (N entradas, M bytes); aceptable para
 * tamanos tipicos de modulo.  Si el coste se vuelve relevante en
 * el futuro, sustituir por una std::unordered_map<hash, idx>.
 */
namespace {
/**
 * @brief FNV-1a 64 sobre un buffer.  Mismo algoritmo que el .vxi.
 *        Local al TU para no introducir dep circular con vx/.
 */
inline uint64_t fnv1a_local_64(const uint8_t *p, size_t n) noexcept {
    // La semilla y el primo viven en util/fnv.h, no aqui.
    return util::fnv_bytes(util::kFnvOffset, p, n);
}
} // namespace

/* ==================== StaticDataStore: implementacion ==================== */

size_t IrModule::StaticDataStore::push_back(const uint8_t *p, size_t n) {
    // Padding hasta multiplo de alignment_default.
    if (alignment_default > 1) {
        while (bytes.size() % alignment_default != 0)
            bytes.push_back(0);
    }
    const uint32_t off = static_cast<uint32_t>(bytes.size());
    bytes.insert(bytes.end(), p, p + n);
    Entry e;
    e.byte_offset = off;
    e.byte_len = static_cast<uint32_t>(n);
    e.meta.content_hash = fnv1a_local_64(p, n);
    entries.push_back(e);
    return entries.size() - 1;
}

size_t IrModule::StaticDataStore::push_back(std::vector<uint8_t> &&v) {
    // Mismo path: copia desde el vector al pool (no se puede evitar
    // copia porque el pool requiere bytes contiguos en su propio buffer).
    return push_back(v.data(), v.size());
}

void IrModule::StaticDataStore::append_raw_entries(StaticDataStore &&other) {
    // añade los bytes de @c other.bytes al final del pool propio
    // (con padding intermedio) y ajusta los offsets de las entries.
    if (other.entries.empty()) return;
    // Padding hasta alignment_default antes del bloque del dep.
    if (alignment_default > 1) {
        while (bytes.size() % alignment_default != 0)
            bytes.push_back(0);
    }
    const uint32_t base_offset = static_cast<uint32_t>(bytes.size());
    bytes.insert(bytes.end(), other.bytes.begin(), other.bytes.end());
    entries.reserve(entries.size() + other.entries.size());
    for (auto &e : other.entries) {
        e.byte_offset += base_offset;
        entries.push_back(std::move(e));
    }
    other.bytes.clear();
    other.entries.clear();
}

/* ==================== intern_static_data ==================== */

uint64_t IrModule::intern_static_data(std::vector<uint8_t> bytes) {
    // Dedup lineal por bytes.  Para programas tipicos (decenas a
    // cientos de literales) el coste es despreciable; arquitectura
    // futura podria añadir un map<hash, idx> si el problema escala.
    const uint64_t h = fnv1a_local_64(bytes.data(), bytes.size());
    for (size_t i = 0; i < static_data.size(); ++i) {
        if (static_data.meta_at(i).content_hash == h &&
            static_data.equals(i, bytes)) {
            return static_cast<uint64_t>(i);
        }
    }
    return static_cast<uint64_t>(static_data.push_back(std::move(bytes)));
}

/**
 * @brief Registra (con deduplicacion) un par (lib, name) en native_imports.
 *
 * Comparacion lineal sobre native_imports.  El frontend Vesta puede
 * llamar a esta funcion desde cada CALLN sin preocuparse por
 * duplicados; el numero tipico de imports nativos por modulo es
 * pequeno (decenas como mucho), por lo que la busqueda lineal es
 * trivialmente mas barata que mantener una tabla hash auxiliar.
 */
void IrModule::register_native_import(std::string lib, std::string name) {
    register_native_import(std::move(lib), std::move(name), IrNativeEffects{});
}

/**
 * @brief Igual, pero declarando lo que la nativa hace.
 *
 * Si la pareja ya estaba registrada sin declaracion, esta la completa: que se
 * sepa o no lo que hace una funcion no puede depender del orden en que se
 * emitieron sus llamadas.
 */
void IrModule::register_native_import(std::string lib, std::string name,
                                      const IrNativeEffects &efectos) {
    for (auto &ni : native_imports) {
        if (ni.lib == lib && ni.name == name) {
            if (efectos.declarados && !ni.efectos.declarados)
                ni.efectos = efectos;
            return;
        }
    }
    native_imports.push_back({std::move(lib), std::move(name), efectos});
}

/**
 * @brief Busca lo declarado para una nativa por su nombre "lib:fn".
 *
 * Busqueda lineal, como el registro: los imports nativos de un modulo son
 * decenas como mucho.
 */
const IrNativeEffects *
IrModule::native_effects_of(const std::string &lib_fn) const {
    const size_t sep = lib_fn.rfind(':');
    if (sep == std::string::npos) return nullptr;
    for (const auto &ni : native_imports) {
        if (!ni.efectos.declarados) continue;
        if (ni.name.size() == lib_fn.size() - sep - 1 &&
            lib_fn.compare(sep + 1, std::string::npos, ni.name) == 0 &&
            ni.lib.size() == sep && lib_fn.compare(0, sep, ni.lib) == 0)
            return &ni.efectos;
    }
    return nullptr;
}

/* =====================================================================
 * ir_print: serializar a texto
 * ===================================================================== */

/**
 * @brief Imprime un valor por su nombre.
 */
static void print_val(std::ostream &o, const IrFunction &fn, IrValueId id) {
    if (id == IR_NO_VALUE) {
        o << "<void>";
        return;
    }
    if (id < static_cast<IrValueId>(fn.values.size()) &&
        !fn.values[id].name.empty()) {
        o << fn.values[id].name;
        return;
    }
    /* Sin nombre, el identificador.  Los nombres NO viajan dentro del
     * artefacto -- son para leer, no para ejecutar -- asi que al explicar un
     * fallo con el intermedio que va en el `.velb` salia `= load.i64` sin
     * destino y las llamadas sin argumentos, como si no tuvieran.  Un valor
     * siempre tiene identificador, y con el se sigue el flujo igual. */
    o << "%" << id;
}

/**
 * @brief Imprime el nombre de un bloque por su id.
 */
static void print_block_name(std::ostream &o, const IrFunction &fn,
                             IrBlockId id) {
    if (id < static_cast<IrBlockId>(fn.blocks.size()))
        o << fn.blocks[id].name;
    else
        o << "?bb" << id;
}

/**
 * @brief Imprime una instruccion en formato texto.
 */
void print_instr(std::ostream &o, const IrFunction &fn, const IrInstr &ins) {
    o << "    "; // indentacion de 4 espacios

    // prefijo de asignacion: %dst = op[.type] ...
    if (ins.dst != IR_NO_VALUE) {
        print_val(o, fn, ins.dst);
        /* Y DE QUE MEMORIA es, cuando es una direccion del anfitrion.
         *
         * Es lo unico que distingue dos instrucciones que se leen igual y
         * hacen cosas distintas: una lee de la memoria de la maquina virtual y
         * la otra de la del proceso.  Equivocarse ahi no da un error, da otro
         * valor -- y el volcado, que es donde se mira cuando algo no cuadra, no
         * lo decia.  Hubo que deducirlo instruccion a instruccion mas de una
         * vez. */
        if (ins.dst < static_cast<IrValueId>(fn.values.size()) &&
            fn.values[ins.dst].is_host_ptr)
            o << "@host";
        o << " = ";
    }

    // nombre del opcode; para comparaciones el tipo va en el nombre
    o << ir_op_name(ins.op);

    // sufijo de tipo (excepto para ops sin tipo como br/ret-void/nop)
    bool print_type = (ins.type != IrType::VOID);
    // BR, TRYLEAVE, NOP, UNREACHABLE, YIELD no tienen tipo
    if (ins.op == IrOp::BR || ins.op == IrOp::UNREACHABLE ||
        ins.op == IrOp::NOP || ins.op == IrOp::TRYLEAVE ||
        ins.op == IrOp::YIELD || ins.op == IrOp::MONENTER ||
        ins.op == IrOp::MONEXIT || ins.op == IrOp::MONWAIT ||
        ins.op == IrOp::MONNOTI || ins.op == IrOp::MONNOTA ||
        ins.op == IrOp::THROW || ins.op == IrOp::FULFILL ||
        ins.op == IrOp::REJECT || ins.op == IrOp::STORE ||
        ins.op == IrOp::SETFIELD || ins.op == IrOp::RESUME ||
        ins.op == IrOp::SWAPCTX || ins.op == IrOp::MEMCPY ||
        ins.op == IrOp::MEMSET || ins.op == IrOp::TRYENTER ||
        ins.op == IrOp::GCWB_IR || ins.op == IrOp::GCDEREF_IR ||
        ins.op == IrOp::ARRAY_STORE || ins.op == IrOp::RETHROW ||
        ins.op == IrOp::RSPAWN_RETURN || ins.op == IrOp::SMARTPTR_FREE ||
        ins.op == IrOp::STRFINALIZE || ins.op == IrOp::VEC_UNOP ||
        ins.op == IrOp::VEC_BINOP || ins.op == IrOp::VEC_FMA ||
        ins.op == IrOp::VEC_ACC_ZERO || ins.op == IrOp::VEC_ACC_ADD ||
        ins.op == IrOp::VEC_ACC_FMA || ins.op == IrOp::VEC_ACC_STORE ||
        ins.op == IrOp::VEC_ACC_COMBINE || ins.op == IrOp::VEC_BINOP_S ||
        ins.op == IrOp::VEC_FMA_S || ins.op == IrOp::VEC_BCAST) {
        print_type = false;
    }
    if (print_type) o << "." << ir_type_name(ins.type);

    switch (ins.op) {
    case IrOp::CONST:
        // const.T imm
        o << " " << ins.imm;
        break;

    case IrOp::BR:
        // br label
        o << " ";
        print_block_name(o, fn, ins.target_block);
        break;

    case IrOp::BR_COND:
        // br.cond %cond, true_lbl, false_lbl
        o << " ";
        if (!ins.operands.empty()) print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_block_name(o, fn, ins.target_block);
        o << ", ";
        print_block_name(o, fn, ins.false_block);
        break;

    case IrOp::RET:
        // ret.T %val  o  ret.void
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        break;

    case IrOp::PHI: {
        // phi.T [%v0, lbl0], [%v1, lbl1], ...
        for (const auto &arg : ins.phi_args) {
            o << " [";
            print_val(o, fn, arg.value);
            o << ", ";
            print_block_name(o, fn, arg.block);
            o << "]";
        }
        break;
    }

    case IrOp::CALL:
    case IrOp::TAILCALL:
        // call.T @fn(args...)
        o << " @" << ins.func_name << "(";
        for (size_t i = 0; i < ins.operands.size(); i++) {
            if (i) o << ", ";
            print_val(o, fn, ins.operands[i]);
        }
        o << ")";
        break;

    case IrOp::CALLN:
        // calln.T @lib:func(args...)
        o << " @" << ins.func_name << "(";
        for (size_t i = 0; i < ins.operands.size(); i++) {
            if (i) o << ", ";
            print_val(o, fn, ins.operands[i]);
        }
        o << ")";
        break;

    case IrOp::CALLIND:
        // callind.T %fn_ptr(args...)
        o << " ";
        print_val(o, fn, ins.func_ptr);
        o << "(";
        for (size_t i = 0; i < ins.operands.size(); i++) {
            if (i) o << ", ";
            print_val(o, fn, ins.operands[i]);
        }
        o << ")";
        break;

    case IrOp::CALLCLOSURE:
        // Invocacion de closure: callclosure.T %fn_ptr, %env(args...)
        // %fn_ptr en func_ptr, %env en operands[0], args declarados
        // en operands[1..].  Notacion textual elegida para que sea
        // visualmente similar a CALLIND pero exhiba el env.
        o << " ";
        print_val(o, fn, ins.func_ptr);
        o << ", ";
        if (!ins.operands.empty()) print_val(o, fn, ins.operands[0]);
        o << "(";
        for (size_t i = 1; i < ins.operands.size(); i++) {
            if (i > 1) o << ", ";
            print_val(o, fn, ins.operands[i]);
        }
        o << ")";
        break;

    case IrOp::MAKE_CLOSURE: {
        // B.1 marker: make_closure @helper, env_kind=K, mutable_mask=M,
        //                          captures=[%c0, %c1, ...]
        // No produce SSA value.  El C2 lo consume para escape analysis.
        const uint64_t env_kind = ins.imm & 0x1ULL;
        const uint64_t mutable_mask = (ins.imm >> 1) & 0xFFFFULL;
        o << " @" << ins.func_name
          << ", env_kind=" << (env_kind ? "GC_HEAP" : "STACK")
          << ", mutable_mask=0x" << std::hex << mutable_mask << std::dec
          << ", captures=[";
        for (size_t i = 0; i < ins.operands.size(); i++) {
            if (i > 0) o << ", ";
            print_val(o, fn, ins.operands[i]);
        }
        o << "]";
        break;
    }

    case IrOp::MAKE_VARIANT: {
        // B.2 marker: make_variant @"Enum.Variant", tag=K, payload=[%p0, %p1,
        // ...]
        o << " @" << ins.func_name << ", tag=" << ins.imm << ", payload=[";
        for (size_t i = 0; i < ins.operands.size(); i++) {
            if (i > 0) o << ", ";
            print_val(o, fn, ins.operands[i]);
        }
        o << "]";
        break;
    }

    case IrOp::MATCH_VARIANT: {
        // B.2 marker: match_variant %scrutinee, @EnumName, n_arms=K
        o << " ";
        if (!ins.operands.empty()) print_val(o, fn, ins.operands[0]);
        o << ", @" << ins.func_name << ", n_arms=" << ins.imm;
        break;
    }

    case IrOp::SWITCH_DENSE: {
        // switch_dense %tag, min=M, default=BB, [t0, t1, ...]
        o << " ";
        if (!ins.operands.empty()) print_val(o, fn, ins.operands[0]);
        o << ", min=" << static_cast<int64_t>(ins.imm & 0xFFFFFFFFu)
          << (((ins.imm >> 32) & 1u) ? " no_bounds" : "") << ", default=BB"
          << ins.target_block << ", [";
        for (size_t i = 0; i < ins.jump_targets.size(); ++i) {
            if (i) o << ", ";
            o << "BB" << ins.jump_targets[i];
        }
        o << "]";
        break;
    }

    case IrOp::CALLVIRT:
        // callvirt.T %obj, vtbl_idx(args...)
        o << " ";
        if (!ins.operands.empty()) print_val(o, fn, ins.operands[0]);
        o << ", " << ins.imm << "(";
        for (size_t i = 1; i < ins.operands.size(); i++) {
            if (i > 1) o << ", ";
            print_val(o, fn, ins.operands[i]);
        }
        o << ")";
        break;

    case IrOp::CALLITF:
        // callitf.T %obj, %params @"Iface\x1fmetodo", idx=K(args...)
        o << " ";
        if (!ins.operands.empty()) print_val(o, fn, ins.operands[0]);
        o << ", ";
        if (ins.operands.size() > 1) print_val(o, fn, ins.operands[1]);
        o << " @\"" << ins.func_name << "\""
          << ", idx=" << (ins.imm & 0xFFFFFFFFULL)
          << ", count=" << (ins.imm >> 32) << "(";
        for (size_t i = 2; i < ins.operands.size(); i++) {
            if (i > 2) o << ", ";
            print_val(o, fn, ins.operands[i]);
        }
        o << ")";
        break;

    case IrOp::ALLOCA:
        // alloca.T count
        o << " " << ins.imm;
        break;

    case IrOp::LOAD:
        // load.T %ptr
        o << " ";
        print_val(o, fn, ins.operands[0]);
        break;

    case IrOp::STORE:
        // store %val, %ptr
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        break;

    case IrOp::MEMSET: // memset %dst, %val, %len (mismo formato)
    case IrOp::MEMCPY:
        // memcpy %dst, %src, %len
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        o << ", ";
        print_val(o, fn, ins.operands[2]);
        break;

    case IrOp::VEC_UNOP:
        // vec_unop.fN %dst_ptr, %a_ptr   imm=(subop<<8)|ancho
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        o << ", imm=" << ins.imm;
        break;

    case IrOp::VEC_BINOP:
    case IrOp::VEC_FMA:
    case IrOp::VEC_ACC_ZERO:
    case IrOp::VEC_ACC_ADD:
    case IrOp::VEC_ACC_FMA:
    case IrOp::VEC_ACC_STORE:
    case IrOp::VEC_ACC_COMBINE:
    case IrOp::VEC_FMA_S:
    case IrOp::VEC_BINOP_S:
        // vec_binop.fN %dst_ptr, %a_ptr[, %b_ptr]   imm=(subop<<8)|ancho.
        // La aridad varia entre estos ops (VEC_ACC_ZERO/COMBINE/STORE tienen 1
        // operando, VEC_ACC_ADD 2, VEC_ACC_FMA/VEC_BINOP 3): imprimimos solo
        // los operandos que existen para no leer fuera de rango.
        for (size_t k = 0; k < ins.operands.size(); ++k) {
            o << (k == 0 ? " " : ", ");
            print_val(o, fn, ins.operands[k]);
        }
        o << ", imm=" << ins.imm;
        break;

    case IrOp::VEC_BCAST:
        // vec_bcast %scalar   imm=ancho
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", imm=" << ins.imm;
        break;

    case IrOp::GETFIELD:
        // getfield.T %obj, field_idx
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", " << ins.imm;
        break;

    case IrOp::SETFIELD:
        // setfield %obj, field_idx, %val
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", " << ins.imm;
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        break;

    case IrOp::SPECIALIZE:
        // specialize.T %class, %types, count
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        o << ", " << ins.imm;
        break;

    case IrOp::TRYENTER:
        // tryenter %handler_pc, %class_ptr
        o << " ";
        print_val(o, fn, ins.operands[0]);
        if (ins.operands.size() > 1) {
            o << ", ";
            print_val(o, fn, ins.operands[1]);
        }
        break;

    case IrOp::FULFILL:
    case IrOp::REJECT:
        // fulfill/reject %future, %value_or_error
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        break;

    case IrOp::MSGSEND:
        // msgsend %pid, %buf_addr, %len
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        o << ", ";
        print_val(o, fn, ins.operands[2]);
        break;

    case IrOp::MSGRECV:
        // msgrecv.T %max_len, %buf_addr
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        break;

    case IrOp::RSPAWN:
        // rspawn %node_idx, %fn_addr
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        break;

    case IrOp::SWAPCTX:
        // swapctx %dst_ctx, %src_ctx
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        break;

    case IrOp::RAW_ASM:
        // raw_asm "texto de ensamblador verbatim"
        o << " \"" << ins.func_name << "\"";
        break;

    case IrOp::ASM_MICRO: {
        // asm_micro #<idx> isa=<n> form=<n> ins=[...] outs=[...] "<plantilla>".
        // Solo para dumps legibles; los detalles viven en fn.asm_micros[imm].
        o << " #" << ins.imm;
        if (ins.imm < fn.asm_micros.size()) {
            const AsmMicro &am = fn.asm_micros[ins.imm];
            o << " isa=" << (unsigned)am.isa << " form=" << am.form_id
              << " eff=" << (unsigned)am.eff;
            if (!ins.operands.empty()) {
                o << " ins=[";
                for (size_t i = 0; i < ins.operands.size(); ++i) {
                    if (i) o << ", ";
                    print_val(o, fn, ins.operands[i]);
                }
                o << "]";
            }
            if (!am.operands.empty()) {
                o << " ops=[";
                for (size_t i = 0; i < am.operands.size(); ++i) {
                    if (i) o << ", ";
                    const auto &op = am.operands[i];
                    o << "$" << i << ":";
                    // rol como flags legibles.
                    if (op.flags & ir::ASM_OP_READ) o << "R";
                    if (op.flags & ir::ASM_OP_WRITE) o << "W";
                    if (op.flags & ir::ASM_OP_IMPLICIT) o << "i";
                    if (op.flags & ir::ASM_OP_SUPPRESSED) o << "s";
                    if (op.flags & ir::ASM_OP_CLOBBER) o << "c";
                    if (op.fixed_phys >= 0) o << "#" << op.fixed_phys;
                    if (op.value != ir::IR_NO_VALUE) {
                        o << " ";
                        print_val(o, fn, op.value);
                    }
                }
                o << "]";
            }
            o << " \"";
            for (char c : am.tmpl) {
                if (c == '\n')
                    o << "\\n";
                else if (c == '"')
                    o << "\\\"";
                else
                    o << c;
            }
            o << "\"";
        }
        break;
    }

    case IrOp::INLINE_ASM: {
        // inline_asm imm=<quals> "<cuerpo NASM con \n escapados>".
        // Formato solo para dumps legibles (--dump-ir); el round-trip
        // real del IR es binario (write_instr serializa imm+func_name).
        o << " imm=" << ins.imm << " \"";
        for (char c : ins.func_name) {
            if (c == '\n')
                o << "\\n";
            else if (c == '"')
                o << "\\\"";
            else
                o << c;
        }
        o << "\"";
        break;
    }

    case IrOp::GEP:
        // gep.ptr %handle, byte_offset
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", " << ins.imm;
        break;

    case IrOp::GCWB_IR:
        // gcwb_ir %handle
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        break;

    case IrOp::GCDEREF_IR:
        // gcderef_ir %handle
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        break;

    case IrOp::GC_DEREF_HOST:
        // %dst = gc_deref_host.ptr %handle
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        break;

    case IrOp::RETHROW:
        // rethrow (sin operandos)
        break;

    case IrOp::SHARED_STAT:
        // shared_stat.T %op_code
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        break;

    case IrOp::READ_VM_REG:
        // read_vm_reg.T imm=N
        o << " " << ins.imm;
        break;

    case IrOp::RSPAWN_RETURN:
        // rspawn_return %payload
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        break;

    case IrOp::SMARTPTR_FREE:
        // smartptr_free.kind=N %ptr [, %del] ["label"]
        o << ".kind=" << ins.imm;
        for (size_t i = 0; i < ins.operands.size(); ++i) {
            o << (i == 0 ? " " : ", ");
            print_val(o, fn, ins.operands[i]);
        }
        if (!ins.func_name.empty()) o << " \"" << ins.func_name << "\"";
        break;

    case IrOp::REFLECT_COUNT:
        // reflect_count.kind=N %cls
        o << ".kind=" << ins.imm;
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        break;

    case IrOp::REFLECT_AT:
        // reflect_at.kind=N %cls, %idx
        o << ".kind=" << ins.imm;
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        if (ins.operands.size() >= 2) {
            o << ", ";
            print_val(o, fn, ins.operands[1]);
        }
        break;

    case IrOp::MOD_LOAD:
        // mod_load.kind=N %path, %len
        o << ".kind=" << ins.imm;
        for (size_t i = 0; i < ins.operands.size(); ++i) {
            o << (i == 0 ? " " : ", ");
            print_val(o, fn, ins.operands[i]);
        }
        break;
    case IrOp::DLOPEN:
        // dlopen %path, %len
        for (size_t i = 0; i < ins.operands.size(); ++i) {
            o << (i == 0 ? " " : ", ");
            print_val(o, fn, ins.operands[i]);
        }
        break;
    case IrOp::DLSYM:
        // dlsym %handle, %name, %len
        for (size_t i = 0; i < ins.operands.size(); ++i) {
            o << (i == 0 ? " " : ", ");
            print_val(o, fn, ins.operands[i]);
        }
        break;

    case IrOp::ARRAY_ALLOC:
        // array_alloc.T %len
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        break;

    case IrOp::ARRAY_LEN:
        // array_len.i64 %arr
        if (!ins.operands.empty()) {
            o << " ";
            print_val(o, fn, ins.operands[0]);
        }
        break;

    case IrOp::ARRAY_LOAD:
        // array_load.T %arr, %idx
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        break;

    case IrOp::ARRAY_STORE:
        // array_store %arr, %idx, %val
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        o << ", ";
        print_val(o, fn, ins.operands[2]);
        break;

    case IrOp::STRMAKE:
        // strmake.handle %buf, %len [enc=imm]
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        if (ins.imm) o << ", " << ins.imm;
        break;

    case IrOp::STRCONV:
        // strconv.handle %str, enc
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", " << ins.imm;
        break;

    case IrOp::STRFINALIZE:
        // strfinalize %str, %new_len
        o << " ";
        print_val(o, fn, ins.operands[0]);
        o << ", ";
        print_val(o, fn, ins.operands[1]);
        break;

    default:
        // instrucciones con 0..N operandos simples:
        // NEG, NOT, FNEG, FABS, FSQRT (1 op)
        // ADD, SUB, MUL, DIV, MOD, CMP_*, FCMP_*, AND, OR, XOR, etc. (2 ops)
        // THROW, MONENTER, MONEXIT, MONWAIT, MONNOTI, MONNOTA (1 op)
        // AWAIT (1 op), SPAWN (1 op), RESUME (1 op)
        // INSTANCEOF, CHECKCAST, ISNULL, UNWRAP, CAST, ZEXT, ... (1-2 ops)
        // GETPROC, GETVM, GETMGR, FUTURE, TRYLEAVE, YIELD (0 ops)
        for (size_t i = 0; i < ins.operands.size(); i++) {
            o << (i == 0 ? " " : ", ");
            print_val(o, fn, ins.operands[i]);
        }
        break;
    }
    o << "\n";
}

/**
 * @brief Serializa un IrModule completo al formato de texto SSA IR.
 */
void ir_print(const IrModule &mod, std::ostream &o) {
    // encabezado del modulo
    o << "// SSA IR - VestaVM\n";
    if (!mod.name.empty()) o << "@module " << mod.name << "\n\n";

    // metadatos opcionales de compilacion
    if (!mod.format.empty()) o << "@format " << mod.format << "\n\n";
    for (const auto &sp : mod.spaces) {
        o << "@space " << sp.name << " 0x" << std::hex << sp.ini_address
          << " 0x" << sp.end_address << std::dec << "\n";
    }
    if (!mod.spaces.empty()) o << "\n";
    for (const auto &sec : mod.sections) {
        o << "@section " << sec.name << " " << sec.space_name << " 0x"
          << std::hex << sec.align << std::dec << "\n";
    }
    if (!mod.sections.empty()) o << "\n";

    // declaraciones de libs nativas
    for (const auto &lib : mod.native_libs) {
        o << "@native_lib " << lib << "\n";
    }
    if (!mod.native_libs.empty()) o << "\n";

    // imports
    for (const auto &imp : mod.imports) {
        o << "@import " << imp << "\n";
    }
    if (!mod.imports.empty()) o << "\n";

    // funciones
    for (const auto &fn : mod.functions) {
        // contract: si la funcion es una instanciacion de
        // un template generico, emitir las anotaciones de
        // provenance ANTES del @function.  Asi el round-trip
        // preserva el contract para C2/AOT/tools.
        if (!fn.generic_template_name.empty()) {
            o << "@template_of " << fn.generic_template_name << "\n";
            o << "@type_args [";
            for (size_t i = 0; i < fn.generic_type_args.size(); ++i) {
                if (i > 0) o << ", ";
                o << fn.generic_type_args[i];
            }
            o << "]\n";
        }

        // @function nombre(param: tipo, ...) -> tipo_retorno [flags] {
        o << "@function " << fn.name << "(";
        bool first = true;
        for (IrValueId pid : fn.params) {
            if (!first) o << ", ";
            first = false;
            if (pid < static_cast<IrValueId>(fn.values.size())) {
                const IrValue &pv = fn.values[pid];
                o << pv.name << ": " << ir_type_name(pv.type);
            }
        }
        o << ") -> " << ir_type_name(fn.ret_type);
        if (fn.is_native) o << " [native]";
        if (fn.is_variadic) o << " [variadic]";
        o << " {\n";

        // bloques basicos
        for (const auto &bb : fn.blocks) {
            o << bb.name << ":\n";
            for (const auto &ins : bb.instrs) {
                print_instr(o, fn, ins);
            }
        }
        o << "}\n\n";
    }
}

/* =====================================================================
 * ir_parse: deserializar desde texto
 * ===================================================================== */

/**
 * @brief Elimina espacios iniciales y finales de una cadena.
 */
static void trim(std::string &s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) {
        s.clear();
        return;
    }
    size_t e = s.find_last_not_of(" \t\r\n");
    s = s.substr(b, e - b + 1);
}

/**
 * @brief Extrae el nombre del opcode de la parte derecha de una instruccion.
 *
 * El opcode puede ser "add", "cmp.eq", "br.cond", etc.  El sufijo de tipo
 * (p.ej. ".i64") no forma parte del nombre del opcode.
 *
 * @param rhs   Lado derecho de la instruccion (despues del "=" o la linea
 * completa).
 * @param op    Opcode extraido.
 * @param type  Tipo anotado extraido (VOID si no hay sufijo).
 * @param rest  Resto de la cadena despues del opcode+tipo.
 * @return true si el opcode fue reconocido.
 */
static bool parse_op_and_type(const std::string &rhs, IrOp &op, IrType &type,
                              std::string &rest) {
    type = IrType::VOID;
    rest.clear();

    // separar por primer espacio para aislar "op[.type]"
    size_t sp = rhs.find(' ');
    std::string op_part = (sp == std::string::npos) ? rhs : rhs.substr(0, sp);
    rest = (sp == std::string::npos) ? "" : rhs.substr(sp + 1);
    trim(rest);

    // algunos opcodes tienen puntos: "cmp.eq", "br.cond", "fcmp.lt"
    // Los reconocemos probando nombres compuestos primero (mas largo = mas
    // especifico) Estrategia: intentar match completo "op_part" primero
    // (incluye ".eq" si lo tiene) Si falla, intentar separar en opcode y tipo
    // por el ULTIMO punto.

    // intento de match completo (para "cmp.eq", "br.cond", "fcmp.lt", etc.)
    if (ir_op_parse(op_part.c_str(), op)) return true;

    // no coincide completo: separar nombre y sufijo de tipo por el ultimo '.'
    size_t last_dot = op_part.rfind('.');
    if (last_dot == std::string::npos) return false; // sin tipo, sin match

    std::string op_name = op_part.substr(0, last_dot);
    std::string type_str = op_part.substr(last_dot + 1);

    if (!ir_op_parse(op_name.c_str(), op)) return false;
    ir_type_parse(type_str.c_str(), type); // si no parsea, queda VOID
    return true;
}

/**
 * @brief Extrae un nombre de valor ("%nombre") del inicio de la cadena.
 * @param s   Cadena de entrada.
 * @param out Nombre extraido (con el '%').
 * @return Posicion despues del nombre, o npos si no empieza por '%'.
 */
static size_t extract_val_name(const std::string &s, size_t pos,
                               std::string &out) {
    if (pos >= s.size() || s[pos] != '%') return std::string::npos;
    size_t end = pos + 1;
    while (end < s.size() && (std::isalnum((unsigned char)s[end]) ||
                              s[end] == '_' || s[end] == '.'))
        end++;
    out = s.substr(pos, end - pos);
    return end;
}

/**
 * @brief Parsea una lista de parametros "nombre: tipo, ..." y llena
 * params/values.
 * @param fn         Funcion destino.
 * @param val_map    Mapa nombre->id que se actualiza con los nuevos valores.
 * @param params_str Cadena con los parametros separados por comas.
 */
static void parse_params(IrFunction &fn,
                         std::unordered_map<std::string, IrValueId> &val_map,
                         const std::string &params_str) {
    std::istringstream ps(params_str);
    std::string param;
    while (std::getline(ps, param, ',')) {
        trim(param);
        if (param.empty()) continue;
        size_t colon = param.find(':');
        if (colon == std::string::npos) continue;
        std::string pname = param.substr(0, colon);
        std::string ptype = param.substr(colon + 1);
        trim(pname);
        trim(ptype);
        IrType pt = IrType::I64;
        ir_type_parse(ptype.c_str(), pt);
        IrValueId vid = fn.new_value(pt, pname);
        fn.values[vid].is_param = true;
        val_map[pname] = vid;
        fn.params.push_back(vid);
    }
}

/**
 * @brief Parsea un archivo .ir de texto y construye un IrModule.
 */
bool ir_parse(const std::string &text, IrModule &out, std::string &error) {
    std::istringstream ss(text);
    std::string line;
    int lineno = 0;

    // indice de la funcion activa en out.functions (-1 si ninguna)
    int cur_fn_idx = -1;
    IrBlockId cur_bb = IR_NO_BLOCK;

    // mapas por nombre dentro de la funcion actual
    std::unordered_map<std::string, IrValueId> val_map;
    std::unordered_map<std::string, IrBlockId> blk_map;

    // helper: puntero a la funcion activa (evita invalidacion por push_back
    // usando indice)
    auto cur_fn = [&]() -> IrFunction * {
        return cur_fn_idx >= 0 ? &out.functions[static_cast<size_t>(cur_fn_idx)]
                               : nullptr;
    };

    // helper: obtener o crear valor por nombre
    auto get_or_create_val = [&](const std::string &name,
                                 IrType t) -> IrValueId {
        auto it = val_map.find(name);
        if (it != val_map.end()) return it->second;
        IrValueId id = cur_fn()->new_value(t, name);
        val_map[name] = id;
        return id;
    };

    // helper: obtener o crear bloque por nombre
    auto get_or_create_blk = [&](const std::string &name) -> IrBlockId {
        auto it = blk_map.find(name);
        if (it != blk_map.end()) return it->second;
        IrBlockId id = cur_fn()->new_block(name);
        blk_map[name] = id;
        return id;
    };

    bool in_block_comment = false; // estado para /* ... */

    // B.3 contract: estado pendiente para las anotaciones de
    // monomorphizacion (@template_of / @type_args).  Se acumulan
    // hasta que se vea el siguiente @function, momento en que se
    // aplican y se limpian.  Si aparecen sin un @function siguiente
    // (programa malformado), simplemente se descartan al final.
    std::string pending_template_of;
    std::vector<std::string> pending_type_args;

    while (std::getline(ss, line)) {
        lineno++;

        // Eliminar comentarios de bloque /* ... */ (pueden abarcar varias
        // lineas)
        {
            std::string cleaned;
            size_t i = 0;
            while (i < line.size()) {
                if (in_block_comment) {
                    if (i + 1 < line.size() && line[i] == '*' &&
                        line[i + 1] == '/') {
                        in_block_comment = false;
                        i += 2;
                    } else {
                        ++i;
                    }
                } else {
                    if (i + 1 < line.size() && line[i] == '/' &&
                        line[i + 1] == '*') {
                        in_block_comment = true;
                        i += 2;
                    } else if (i + 1 < line.size() && line[i] == '/' &&
                               line[i + 1] == '/') {
                        break; // resto de la linea es comentario
                    } else if (line[i] == ';') {
                        break; // comentario estilo ensamblador
                    } else {
                        cleaned += line[i++];
                    }
                }
            }
            line = cleaned;
        }

        trim(line);
        if (line.empty()) continue;

        // --- @module nombre ---
        if (line.rfind("@module", 0) == 0) {
            out.name = line.substr(7);
            trim(out.name);
            continue;
        }

        // --- @format nombre ---  (p.ej. @format velb)
        if (line.rfind("@format", 0) == 0) {
            out.format = line.substr(7);
            trim(out.format);
            continue;
        }

        // --- @space nombre ini_hex end_hex ---
        // Ejemplo: @space anonymous 0x0000000000000000 0xFFFFFFFFFFFFFFFF
        if (line.rfind("@space", 0) == 0) {
            std::istringstream ss2(line.substr(6));
            IrSpaceDef sp;
            std::string ini_s, end_s;
            ss2 >> sp.name >> ini_s >> end_s;
            try {
                sp.ini_address = std::stoull(ini_s, nullptr, 0);
                sp.end_address = std::stoull(end_s, nullptr, 0);
            } catch (...) {
                sp.ini_address = 0;
                sp.end_address = 0xFFFFFFFFFFFFFFFFULL;
            }
            out.spaces.push_back(sp);
            continue;
        }

        // --- @section nombre espacio align_hex ---
        // Ejemplo: @section code anonymous 0x1000
        if (line.rfind("@section", 0) == 0) {
            std::istringstream ss2(line.substr(8));
            IrSectionDef sec;
            std::string align_s;
            ss2 >> sec.name >> sec.space_name >> align_s;
            try {
                sec.align = std::stoull(align_s, nullptr, 0);
            } catch (...) {
                sec.align = 0x1000;
            }
            out.sections.push_back(sec);
            continue;
        }

        // --- @native_lib nombre ---
        if (line.rfind("@native_lib", 0) == 0) {
            std::string lib = line.substr(11);
            trim(lib);
            out.native_libs.push_back(lib);
            continue;
        }

        // --- @import nombre ---
        if (line.rfind("@import", 0) == 0) {
            std::string imp = line.substr(7);
            trim(imp);
            out.imports.push_back(imp);
            continue;
        }

        // --- @template_of <TemplateName> --- (contract)
        // Anotacion que aplica al siguiente @function: marca esta
        // como una instanciacion del template indicado.
        if (line.rfind("@template_of", 0) == 0) {
            pending_template_of = line.substr(12);
            trim(pending_template_of);
            continue;
        }

        // --- @type_args [t1, t2, ...] --- (contract)
        // Lista de tipos concretos sustituidos en la instanciacion.
        // Se aplica al siguiente @function junto con @template_of.
        if (line.rfind("@type_args", 0) == 0) {
            std::string body = line.substr(10);
            // Quitar `[` y `]` si estan presentes.
            size_t lb = body.find('[');
            size_t rb = body.find(']');
            if (lb != std::string::npos) body.erase(0, lb + 1);
            if (rb != std::string::npos && rb > 0) {
                size_t rb2 = body.find(']');
                if (rb2 != std::string::npos) body.erase(rb2);
            }
            // Split por coma.
            pending_type_args.clear();
            std::string acc;
            for (char c : body) {
                if (c == ',') {
                    trim(acc);
                    if (!acc.empty()) pending_type_args.push_back(acc);
                    acc.clear();
                } else {
                    acc += c;
                }
            }
            trim(acc);
            if (!acc.empty()) pending_type_args.push_back(acc);
            continue;
        }

        // --- @function nombre(...) -> tipo [flags] { ---
        if (line.rfind("@function", 0) == 0) {
            IrFunction fn;
            fn.is_native = false;
            fn.is_variadic = false;
            fn.ret_type = IrType::VOID;

            // Aplicar anotaciones pendientes del contract.
            if (!pending_template_of.empty()) {
                fn.generic_template_name = std::move(pending_template_of);
                fn.generic_type_args = std::move(pending_type_args);
                pending_template_of.clear();
                pending_type_args.clear();
            }

            size_t paren = line.find('(');
            if (paren == std::string::npos) {
                error =
                    "linea " + std::to_string(lineno) + ": @function sin '('";
                return false;
            }
            fn.name = line.substr(10, paren - 10);
            trim(fn.name);

            if (line.find("[native]") != std::string::npos) fn.is_native = true;
            if (line.find("[variadic]") != std::string::npos)
                fn.is_variadic = true;

            // parsear tipo de retorno (tras "->")
            size_t arrow = line.find("-> ");
            if (arrow != std::string::npos) {
                std::string rt = line.substr(arrow + 3);
                size_t end = rt.find_first_of(" \t{[");
                if (end != std::string::npos) rt = rt.substr(0, end);
                IrType t;
                if (ir_type_parse(rt.c_str(), t)) fn.ret_type = t;
            }

            // crear el bloque de entrada antes de parsear params
            fn.new_block("entry");

            // anadir la funcion al modulo antes de parsear params
            // (para que los lambdas get_or_create_val/blk funcionen)
            out.functions.push_back(std::move(fn));
            cur_fn_idx = static_cast<int>(out.functions.size()) - 1;
            cur_bb = 0; // bloque "entry" = id 0
            val_map.clear();
            blk_map.clear();
            blk_map["entry"] = 0;

            // parsear parametros: nombre: tipo, ...
            size_t close_paren = line.find(')', paren);
            if (close_paren != std::string::npos && close_paren > paren + 1) {
                std::string params_str =
                    line.substr(paren + 1, close_paren - paren - 1);
                parse_params(*cur_fn(), val_map, params_str);
            }
            continue;
        }

        // --- cierre de funcion "}" ---
        if (line == "}") {
            cur_fn_idx = -1;
            cur_bb = IR_NO_BLOCK;
            val_map.clear();
            blk_map.clear();
            continue;
        }

        if (!cur_fn()) continue; // linea fuera de funcion

        // --- etiqueta de bloque "nombre:" ---
        if (line.back() == ':' && line.find(' ') == std::string::npos) {
            std::string bname = line.substr(0, line.size() - 1);
            cur_bb = get_or_create_blk(bname);
            continue;
        }

        // --- instruccion ---
        if (cur_bb == IR_NO_BLOCK) cur_bb = get_or_create_blk("body");

        IrInstr ins;
        ins.source_line = static_cast<uint32_t>(lineno);

        // detectar asignacion: "dst = rhs" (con o sin prefijo %)
        std::string rhs = line;
        {
            size_t eq = line.find(" = ");
            if (eq != std::string::npos) {
                std::string dst_name = line.substr(0, eq);
                trim(dst_name);
                // nombre valido: sin espacios, no vacio, no empieza por '@'
                if (!dst_name.empty() &&
                    dst_name.find(' ') == std::string::npos &&
                    dst_name[0] != '@') {
                    rhs = line.substr(eq + 3);
                    trim(rhs);
                    // tipo provisional; se corrige al parsear el opcode
                    ins.dst = get_or_create_val(dst_name, IrType::I64);
                }
            }
        }

        // parsear opcode y tipo anotado
        IrOp parsed_op = IrOp::NOP;
        IrType parsed_type = IrType::VOID;
        std::string operand_str;
        if (!parse_op_and_type(rhs, parsed_op, parsed_type, operand_str)) {
            ins.op = IrOp::NOP; // opcode desconocido: emitir NOP
            cur_fn()->append(cur_bb, std::move(ins));
            continue;
        }
        ins.op = parsed_op;
        ins.type = parsed_type;

        // actualizar tipo del destino si se conoce
        if (ins.dst != IR_NO_VALUE && parsed_type != IrType::VOID)
            cur_fn()->values[ins.dst].type = parsed_type;

        // parsear operandos segun el opcode
        switch (ins.op) {
        case IrOp::CONST: {
            // const.T imm
            trim(operand_str);
            try {
                ins.imm = std::stoull(operand_str);
            } catch (...) {
                ins.imm = 0;
            }
            break;
        }

        case IrOp::BR: {
            // br label
            trim(operand_str);
            ins.target_block = get_or_create_blk(operand_str);
            break;
        }

        case IrOp::BR_COND: {
            // br.cond %cond, true_lbl, false_lbl
            std::istringstream cs(operand_str);
            std::string tok;
            int field = 0;
            while (std::getline(cs, tok, ',')) {
                trim(tok);
                if (field == 0) {
                    ins.operands.push_back(
                        get_or_create_val(tok, IrType::BOOL));
                } else if (field == 1) {
                    ins.target_block = get_or_create_blk(tok);
                } else {
                    ins.false_block = get_or_create_blk(tok);
                }
                field++;
            }
            break;
        }

        case IrOp::RET: {
            // ret.T val  o  ret.void (sin operandos)
            trim(operand_str);
            if (!operand_str.empty()) {
                ins.operands.push_back(
                    get_or_create_val(operand_str, ins.type));
            }
            break;
        }

        case IrOp::PHI: {
            // phi.T [%v0, lbl0], [%v1, lbl1], ...
            std::string s = operand_str;
            size_t pos = 0;
            while (pos < s.size()) {
                size_t ob = s.find('[', pos);
                if (ob == std::string::npos) break;
                size_t cb = s.find(']', ob);
                if (cb == std::string::npos) break;
                std::string pair = s.substr(ob + 1, cb - ob - 1);
                size_t comma = pair.find(',');
                if (comma != std::string::npos) {
                    std::string vname = pair.substr(0, comma);
                    std::string bname = pair.substr(comma + 1);
                    trim(vname);
                    trim(bname);
                    IrPhiArg arg;
                    arg.value = get_or_create_val(vname, ins.type);
                    arg.block = get_or_create_blk(bname);
                    ins.phi_args.push_back(arg);
                }
                pos = cb + 1;
            }
            break;
        }

        case IrOp::CALL:
        case IrOp::CALLN:
        case IrOp::TAILCALL: {
            // call.T @fn(args...) o calln.T @lib:func(args...)
            size_t at = operand_str.find('@');
            if (at == std::string::npos) break;
            size_t lparen = operand_str.find('(', at);
            if (lparen == std::string::npos) {
                ins.func_name = operand_str.substr(at + 1);
            } else {
                ins.func_name = operand_str.substr(at + 1, lparen - at - 1);
                // parsear argumentos
                size_t rparen = operand_str.rfind(')');
                std::string args_str =
                    operand_str.substr(lparen + 1, rparen == std::string::npos
                                                       ? std::string::npos
                                                       : rparen - lparen - 1);
                std::istringstream as(args_str);
                std::string arg;
                while (std::getline(as, arg, ',')) {
                    trim(arg);
                    if (!arg.empty())
                        ins.operands.push_back(
                            get_or_create_val(arg, IrType::I64));
                }
            }
            break;
        }

        case IrOp::RAW_ASM: {
            // raw_asm "texto..." — extraer contenido entre comillas
            // Soporta secuencias de escape \n \t \\ dentro del string.
            size_t q1 = operand_str.find('"');
            size_t q2 = (q1 != std::string::npos) ? operand_str.rfind('"')
                                                  : std::string::npos;
            if (q1 != std::string::npos && q2 != q1) {
                std::string raw = operand_str.substr(q1 + 1, q2 - q1 - 1);
                // expandir secuencias de escape basicas
                std::string expanded;
                expanded.reserve(raw.size());
                for (size_t i = 0; i < raw.size(); ++i) {
                    if (raw[i] == '\\' && i + 1 < raw.size()) {
                        ++i;
                        switch (raw[i]) {
                        case 'n': expanded += '\n'; break;
                        case 't': expanded += '\t'; break;
                        case '\\': expanded += '\\'; break;
                        case '"': expanded += '"'; break;
                        default:
                            expanded += '\\';
                            expanded += raw[i];
                            break;
                        }
                    } else {
                        expanded += raw[i];
                    }
                }
                ins.func_name = std::move(expanded);
            }
            // RAW_ASM nunca tiene dst ni operandos
            ins.dst = IR_NO_VALUE;
            ins.type = IrType::VOID;
            break;
        }

        case IrOp::ALLOCA: {
            // alloca.T count
            trim(operand_str);
            try {
                ins.imm = std::stoull(operand_str);
            } catch (...) {
                ins.imm = 1;
            }
            break;
        }

        case IrOp::GETFIELD:
        case IrOp::GEP: {
            // getfield.T %obj, field_offset  /  gep.ptr %handle, byte_offset
            std::istringstream gs(operand_str);
            std::string tok;
            int field = 0;
            while (std::getline(gs, tok, ',')) {
                trim(tok);
                if (field == 0)
                    ins.operands.push_back(
                        get_or_create_val(tok, IrType::HANDLE));
                else
                    try {
                        ins.imm = std::stoull(tok);
                    } catch (...) {
                    }
                field++;
            }
            break;
        }

        case IrOp::STRMAKE:
        case IrOp::STRCONV: {
            // strmake.handle %buf, %len [, enc]
            // strconv.handle %str, enc
            std::istringstream gs(operand_str);
            std::string tok;
            int field = 0;
            while (std::getline(gs, tok, ',')) {
                trim(tok);
                if (tok.empty()) continue;
                bool is_ident =
                    (tok[0] == '%' || std::isalpha((unsigned char)tok[0]) ||
                     tok[0] == '_');
                if (is_ident) {
                    ins.operands.push_back(get_or_create_val(tok, IrType::I64));
                } else {
                    // ultimo campo es enc (literal numerico)
                    try {
                        ins.imm = std::stoull(tok);
                    } catch (...) {
                    }
                }
                field++;
            }
            break;
        }

        default: {
            // instrucciones con 0..N operandos simples separados por ','
            if (operand_str.empty()) break;
            std::istringstream ds(operand_str);
            std::string tok;
            while (std::getline(ds, tok, ',')) {
                trim(tok);
                if (tok.empty()) continue;
                // Aceptar nombres de valor con prefijo '%' o como identificador
                // simple (letra/_); ignorar literales numericos puros.
                bool is_ident =
                    (tok[0] == '%' || std::isalpha((unsigned char)tok[0]) ||
                     tok[0] == '_');
                if (is_ident) {
                    ins.operands.push_back(get_or_create_val(tok, IrType::I64));
                }
            }
            break;
        }
        }

        cur_fn()->append(cur_bb, std::move(ins));
    }

    return true;
}

/* =====================================================================
 * ir_verify: verificador de forma SSA
 * ===================================================================== */

/**
 * @brief Verifica que el modulo esta en forma SSA correcta.
 */
bool ir_verify(const IrModule &mod, std::vector<std::string> &errors) {
    bool ok = true;

    for (const auto &fn : mod.functions) {
        // conjunto de valores definidos (SSA: cada uno exactamente una vez)
        std::unordered_map<IrValueId, int> def_count;
        for (const auto &v : fn.values)
            def_count[v.id] = 0;

        // los parametros cuentan como definidos
        for (IrValueId pid : fn.params) {
            if (def_count.count(pid)) def_count[pid]++;
        }

        for (const auto &bb : fn.blocks) {
            bool has_terminator = false;

            for (const auto &ins : bb.instrs) {
                // contar definiciones
                if (ins.dst != IR_NO_VALUE) {
                    def_count[ins.dst]++;
                    if (def_count[ins.dst] > 1) {
                        errors.push_back(
                            "fn '" + fn.name + "' bloque '" + bb.name +
                            "': valor " + std::to_string(ins.dst) +
                            " definido mas de una vez (viola SSA)");
                        ok = false;
                    }
                }

                // verificar terminadores
                if (ir_op_ends_block(ins.op)) {
                    // Y que sea el ULTIMO.  No es una regla de estilo: quien
                    // recalcula las aristas del grafo lee la ULTIMA
                    // instruccion del bloque para saber a donde salta.  Si hay
                    // algo detras, ese bloque se queda sin salidas -- y lo que
                    // fuera detras, sin ejecutarse.
                    if (has_terminator || &ins != &bb.instrs.back()) {
                        // Con el sitio: "hay un problema" no basta para ir a
                        // buscarlo en un bloque de cincuenta instrucciones.
                        const size_t pos =
                            static_cast<size_t>(&ins - &bb.instrs.front());
                        errors.push_back(
                            "fn '" + fn.name + "' bloque '" + bb.name +
                            "': el terminador " + ir_op_name(ins.op) +
                            " esta en la posicion " + std::to_string(pos) +
                            " de " + std::to_string(bb.instrs.size()) +
                            "; detras queda " +
                            ir_op_name(bb.instrs.back().op));
                        ok = false;
                    }
                    has_terminator = true;
                }

                // verificar que los operandos existen
                for (IrValueId op_id : ins.operands) {
                    if (op_id != IR_NO_VALUE &&
                        op_id >= static_cast<IrValueId>(fn.values.size())) {
                        errors.push_back("fn '" + fn.name + "' bloque '" +
                                         bb.name + "': operando " +
                                         std::to_string(op_id) +
                                         " fuera del rango del pool");
                        ok = false;
                    }
                }
                // verificar func_ptr para CALLIND y CALLCLOSURE.
                if ((ins.op == IrOp::CALLIND || ins.op == IrOp::CALLCLOSURE) &&
                    ins.func_ptr != IR_NO_VALUE &&
                    ins.func_ptr >= static_cast<IrValueId>(fn.values.size())) {
                    errors.push_back(
                        "fn '" + fn.name + "': callind/closure func_ptr " +
                        std::to_string(ins.func_ptr) + " fuera del rango");
                    ok = false;
                }
                // verificar phi args
                for (const auto &phi_arg : ins.phi_args) {
                    if (phi_arg.value != IR_NO_VALUE &&
                        phi_arg.value >=
                            static_cast<IrValueId>(fn.values.size())) {
                        errors.push_back("fn '" + fn.name + "': phi arg " +
                                         std::to_string(phi_arg.value) +
                                         " fuera del rango");
                        ok = false;
                    }
                }
            }

            // bloque no vacio sin terminador
            if (!has_terminator && !bb.instrs.empty()) {
                errors.push_back("fn '" + fn.name + "' bloque '" + bb.name +
                                 "': sin instruccion terminadora");
                ok = false;
            }
        }
    }

    return ok;
}

void IrFunction::recompute_edges() {
    const size_t N = blocks.size();
    for (size_t b = 0; b < N; ++b) {
        blocks[b].succs.clear();
        blocks[b].preds.clear();
    }
    for (size_t b = 0; b < N; ++b) {
        if (blocks[b].instrs.empty()) continue;
        const IrInstr &t = blocks[b].instrs.back();
        auto add = [&](IrBlockId s) {
            if (s != IR_NO_BLOCK && s < N) blocks[b].succs.push_back(s);
        };
        if (t.op == IrOp::BR) {
            add(t.target_block);
        } else if (t.op == IrOp::BR_COND) {
            add(t.target_block);
            add(t.false_block);
        } else if (t.op == IrOp::SWITCH_DENSE) {
            add(t.target_block);
            for (IrBlockId s : t.jump_targets)
                add(s);
        }
    }
    for (size_t b = 0; b < N; ++b)
        for (IrBlockId s : blocks[b].succs)
            blocks[s].preds.push_back(static_cast<IrBlockId>(b));
}

/* ==================== ir_correr_indices_de_datos ==================== */

void ir_correr_indices_de_datos(IrFunction &fn, uint64_t desplazamiento) {
    /* Una funcion es el caso de una lista de una: asi la regla vive en UN
     * sitio y no puede divergir entre las dos formas de pedirla. */
    std::vector<IrFunction> una;
    una.push_back(std::move(fn));
    ir_correr_indices_de_datos(una, desplazamiento);
    fn = std::move(una[0]);
}

void ir_correr_indices_de_datos(std::vector<IrFunction> &fns,
                                uint64_t desplazamiento) {
    if (desplazamiento == 0) return;
    /* Las referencias TEXTUALES: dentro del ensamblador embebido y de las
     * etiquetas, una ranura se nombra "code.s_<N>". */
    auto correr_texto = [desplazamiento](std::string &s) {
        if (s.find("code.s_") == std::string::npos) return;
        std::string out;
        out.reserve(s.size());
        size_t i = 0;
        while (i < s.size()) {
            const size_t p = s.find("code.s_", i);
            if (p == std::string::npos) {
                out.append(s, i, s.size() - i);
                break;
            }
            out.append(s, i, p - i);
            out.append("code.s_");
            size_t j = p + 7;
            uint64_t num = 0;
            while (j < s.size() && s[j] >= '0' && s[j] <= '9') {
                num = num * 10 + static_cast<uint64_t>(s[j] - '0');
                ++j;
            }
            out.append(std::to_string(num + desplazamiento));
            i = j;
        }
        s = std::move(out);
    };
    for (IrFunction &fn : fns)
        for (IrBlock &bb : fn.blocks)
            for (IrInstr &ins : bb.instrs) {
                if (ins.op == IrOp::STR_LIT_ADDR) {
                    ins.imm += static_cast<int64_t>(desplazamiento);
                    continue;
                }
                if (!ins.func_name.empty()) correr_texto(ins.func_name);
            }
}

} // namespace ir
