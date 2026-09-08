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
 * @file jit/sched/cost_model.cpp
 * @brief Modelo de coste del scheduler: (a) modelo GENERICO (core OoO moderno
 *        balanceado, con un layout sintetico de grupos de puertos) y (b) modelo
 *        por MICROARQUITECTURA que lee los datos EXACTOS de la DB de coste
 *        (@c cost_x86()/@c cost_arm64(), generada desde arch-data): latencia,
 *        throughput reciproco, uops y GRUPOS DE PUERTOS por instruccion.
 *
 * MULTI-ISA: x86-64/x86-32 y arm64.  El mapeo @c MOp -> forma de la DB usa el
 * mnemonico canonico de cada ISA (los MOp enteros genericos se comparten; los
 * @c A64_* son arm64).  La deteccion del core del host (JIT auto) usa @c cpuid
 * en x86 y @c MIDR_EL1 en arm64.
 */

#include "jit/sched/cost_model.h"

#include "jit/sched/machine_effects.h" // mop_mnemonic (MOp -> mnemonico, DRY)
#include "vx/asm/instr_db.h"

#include <cstdlib>
#include <cstring>
#include <string>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||             \
    defined(_M_IX86)
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#define VX_HOST_X86 1
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
#define VX_HOST_ARM64 1
#if defined(__linux__)
#include <sys/auxv.h>
#endif
#endif

namespace jit {
namespace sched {

namespace idb = vx::instr_db;

// ========================================================================
//  Modelo GENERICO: layout sintetico de grupos de puertos de un core OoO
//  moderno balanceado (punto comun de Skylake/Zen/Neoverse).  Grupos con su
//  capacidad (uops/ciclo = numero de puertos fisicos del grupo).
// ========================================================================

namespace {

/// Grupos de puertos del modelo generico (indice == posicion en las tablas).
enum GenPort : uint8_t {
    GP_ALU = 0,    ///< aritmetica/logica entera (4 puertos).
    GP_LOAD = 1,   ///< direcciones/lecturas (2 puertos).
    GP_STORE = 2,  ///< datos de escritura (1 puerto).
    GP_MUL = 3,    ///< multiplicacion entera (1 puerto).
    GP_DIV = 4,    ///< division entera (1 puerto, no pipelined).
    GP_FPADD = 5,  ///< suma/convert FP/SIMD (2 puertos).
    GP_FPMUL = 6,  ///< multiplicacion FP/SIMD (1 puerto).
    GP_FPDIV = 7,  ///< division/raiz FP (1 puerto, no pipelined).
    GP_BRANCH = 8, ///< saltos (2 puertos).
    GP_COUNT = 9
};

/// Capacidad (uops/ciclo) de cada grupo del modelo generico.
const int kGenPortCap[GP_COUNT] = {4, 2, 1, 1, 1, 2, 1, 1, 2};
const char *const kGenPortName[GP_COUNT] = {
    "alu", "load", "store", "mul", "div", "fpadd", "fpmul", "fpdiv", "branch"};

/// Grupo de puertos que usa cada familia de ejecucion (generico).
uint8_t gen_port_for(ExecKind k) {
    switch (k) {
    case ExecKind::ALU: return GP_ALU;
    case ExecKind::MUL: return GP_MUL;
    case ExecKind::DIV: return GP_DIV;
    case ExecKind::LOAD: return GP_LOAD;
    case ExecKind::STORE: return GP_STORE;
    case ExecKind::BRANCH: return GP_BRANCH;
    case ExecKind::FP_ADD: return GP_FPADD;
    case ExecKind::FP_MUL: return GP_FPMUL;
    case ExecKind::FP_DIV: return GP_FPDIV;
    default: return GP_ALU;
    }
}

/// ¿Alguno de los operandos toca MEMORIA? (load/store fusionado en la op).
bool touches_mem(const MInstr &mi) {
    return mi.dst.kind == MOperandKind::MEM ||
           mi.src1.kind == MOperandKind::MEM ||
           mi.src2.kind == MOperandKind::MEM;
}
/// ¿El destino es memoria? (la op ESCRIBE a memoria -> store).
bool writes_mem(const MInstr &mi) {
    return mi.dst.kind == MOperandKind::MEM;
}

} // namespace

InstrCost generic_cost_for(const MInstr &mi) {
    InstrCost c;
    switch (mi.op) {
    /* --- Pseudo-ops / barreras (sin coste de ejecucion) --- */
    case MOp::NOP:
    case MOp::LABEL_DEF:
    case MOp::COMMENT:
    case MOp::ARG:
        c.kind = ExecKind::OTHER;
        c.latency = 0.0f;
        c.recip_tp = 0.0f;
        c.uops = 0.0f;
        c.nports = 0;
        return c;
    case MOp::CALL:
    case MOp::CALL_ABS:
    case MOp::RET:
    case MOp::SAFEPOINT:
        c.kind = ExecKind::OTHER;
        c.latency = 1.0f;
        c.recip_tp = 1.0f;
        c.is_barrier = true;
        c.nports = 0;
        return c;

    /* --- Control de flujo --- */
    case MOp::JMP:
    case MOp::JCC:
        c.kind = ExecKind::BRANCH;
        c.latency = 1.0f;
        c.recip_tp = 1.0f;
        break;

    /* --- Memoria explicita (pseudo LOAD/STORE + VM) --- */
    case MOp::LOAD:
    case MOp::LOAD_VM:
        c.kind = ExecKind::LOAD;
        c.latency = (mi.op == MOp::LOAD_VM) ? 5.0f : 4.0f;
        c.recip_tp = 0.5f;
        break;
    case MOp::STORE:
    case MOp::STORE_VM:
        c.kind = ExecKind::STORE;
        c.latency = 1.0f;
        c.recip_tp = 1.0f;
        break;

    /* --- Multiplicacion / division entera --- */
    case MOp::IMUL:
        c.kind = ExecKind::MUL;
        c.latency = 3.0f;
        c.recip_tp = 1.0f;
        break;
    case MOp::IDIV:
    case MOp::DIV_U:
        c.kind = ExecKind::DIV;
        c.latency = 20.0f;
        c.recip_tp = 12.0f;
        break;

    /* --- Bit ops de latencia media --- */
    case MOp::POPCNT:
    case MOp::LZCNT:
    case MOp::TZCNT:
    case MOp::BSWAP:
        c.kind = ExecKind::ALU;
        c.latency = 3.0f;
        c.recip_tp = 1.0f;
        break;

    /* --- Coma flotante escalar (x86 SSE) --- */
    case MOp::ADDSD:
    case MOp::SUBSD:
    case MOp::MINSD:
    case MOp::MAXSD:
    case MOp::ROUNDSD:
    case MOp::UCOMISD:
    case MOp::CVTSI2SD:
    case MOp::CVTTSD2SI:
    case MOp::CVTSS2SD:
    case MOp::CVTSD2SS:
        c.kind = ExecKind::FP_ADD;
        c.latency = 4.0f;
        c.recip_tp = 0.5f;
        break;
    case MOp::MULSD:
        c.kind = ExecKind::FP_MUL;
        c.latency = 4.0f;
        c.recip_tp = 0.5f;
        break;
    case MOp::DIVSD:
    case MOp::SQRTSD:
        c.kind = ExecKind::FP_DIV;
        c.latency = 14.0f;
        c.recip_tp = 8.0f;
        break;
    case MOp::MOVQ_GP_XMM:
    case MOp::MOVQ_XMM_GP:
        c.kind = ExecKind::FP_ADD;
        c.latency = 3.0f;
        c.recip_tp = 1.0f;
        break;

    /* --- arm64: division/multiplicacion/FP (A64_*) --- */
    case MOp::A64_UDIV:
    case MOp::A64_SDIV:
        c.kind = ExecKind::DIV;
        c.latency = 12.0f;
        c.recip_tp = 6.0f;
        break;
    case MOp::A64_MADD:
    case MOp::A64_MSUB:
        c.kind = ExecKind::MUL;
        c.latency = 3.0f;
        c.recip_tp = 1.0f;
        break;
    case MOp::A64_FADD:
    case MOp::A64_FSUB:
    case MOp::A64_FCMP:
    case MOp::A64_FMOV:
    case MOp::A64_FNEG:
    case MOp::A64_FABS:
    case MOp::A64_SCVTF:
    case MOp::A64_UCVTF:
    case MOp::A64_FCVTZS:
    case MOp::A64_FCVTZU:
    case MOp::A64_FCVT:
        c.kind = ExecKind::FP_ADD;
        c.latency = 3.0f;
        c.recip_tp = 0.5f;
        break;
    case MOp::A64_FMUL:
        c.kind = ExecKind::FP_MUL;
        c.latency = 4.0f;
        c.recip_tp = 0.5f;
        break;
    case MOp::A64_FDIV:
    case MOp::A64_FSQRT:
        c.kind = ExecKind::FP_DIV;
        c.latency = 10.0f;
        c.recip_tp = 6.0f;
        break;

    /* --- ALU entera simple + movimientos (latencia 1) --- */
    default:
        c.kind = ExecKind::ALU;
        c.latency = 1.0f;
        c.recip_tp = 1.0f;
        break;
    }

    // Si ademas TOCA MEMORIA (operando MEM fusionado): una ALU con fuente en
    // memoria = load + op; un store-op (dst en memoria) queda por el puerto de
    // store.  Anade el grupo de load/store al uso de puertos.
    uint8_t mem_group = 0xFF;
    if (touches_mem(mi)) {
        if (writes_mem(mi)) {
            c.kind = ExecKind::STORE;
            if (c.latency < 1.0f) c.latency = 1.0f;
            mem_group = GP_STORE;
        } else {
            c.latency += 4.0f;
            if (c.kind == ExecKind::ALU) c.kind = ExecKind::LOAD;
            mem_group = GP_LOAD;
        }
    }

    // Rellenar los grupos de puertos que ocupa (para el modelo de recursos).
    c.uops = 1.0f;
    c.nports = 0;
    c.ports[c.nports++] = SchedPortUse{gen_port_for(c.kind), 1.0f};
    if (mem_group != 0xFF && mem_group != gen_port_for(c.kind) &&
        c.nports < kMaxSchedPorts) {
        c.ports[c.nports++] = SchedPortUse{mem_group, 1.0f};
        c.uops = 2.0f;
    }
    return c;
}

InstrCost GenericCostModel::cost(const MInstr &mi) const {
    return generic_cost_for(mi);
}
int GenericCostModel::port_count() const {
    return GP_COUNT;
}
int GenericCostModel::port_capacity(int group) const {
    return (group >= 0 && group < GP_COUNT) ? kGenPortCap[group] : 1;
}
const char *GenericCostModel::port_name(int group) const {
    return (group >= 0 && group < GP_COUNT) ? kGenPortName[group] : "?";
}

// ========================================================================
//  Mapeo MOp -> mnemonico canonico de la ISA (para casar la forma en la DB).
// ========================================================================

namespace {

/// Construye los operandos parseados (para casar la forma) desde el MInstr.
void build_ops(const MInstr &mi, std::vector<idb::ParsedOp> &ops) {
    auto add = [&](const MOperand &o) {
        if (o.kind == MOperandKind::NONE) return;
        idb::ParsedOp p;
        switch (o.kind) {
        case MOperandKind::MEM:
            p.kind = idb::OP_MEM;
            p.width = 0;
            break;
        case MOperandKind::IMM32:
        case MOperandKind::IMM64_IDX:
            p.kind = idb::OP_IMM;
            p.width = 0;
            break;
        case MOperandKind::LABEL:
            p.kind = idb::OP_RELBR;
            p.width = 0;
            break;
        default: // REG / VREG / REL_RT -> registro
            p.kind = idb::OP_REG;
            p.width = static_cast<uint16_t>(o.width * 8);
            break;
        }
        ops.push_back(p);
    };
    add(mi.dst);
    add(mi.src1);
    add(mi.src2);
}

/// Cuenta los puertos fisicos que nombra un grupo tipo "p0156" -> 4.
int port_group_capacity(const char *name) {
    if (!name || name[0] != 'p') return 1;
    int n = 0;
    for (const char *s = name + 1; *s; ++s)
        if (*s >= '0' && *s <= '9') ++n;
    return n > 0 ? n : 1;
}

// ========================================================================
//  Modelo por MICROARQUITECTURA: datos exactos de la DB de coste.
// ========================================================================

class UarchCostModel final : public SchedCostModel {
  public:
    UarchCostModel(idb::Isa isa, int32_t ua_id, const idb::MicroarchData *ua,
                   std::string display)
        : isa_(isa), ua_id_(ua_id), ua_(ua), name_(std::move(display)) {}

    InstrCost cost(const MInstr &mi) const override {
        // Mnemonico + forma segun la ISA -> FormID -> AsmCost de la DB.  Reusa
        // el mismo mapeo MOp->mnemonico que usan los efectos DB (DRY).
        const char *mnem = mop_mnemonic(mi.op, isa_);
        if (mnem == nullptr) return generic_cost_for(mi); // pseudo-op
        std::vector<idb::ParsedOp> ops;
        build_ops(mi, ops);
        const int32_t form = idb::match(isa_, mnem, ops);
        if (form < 0) return generic_cost_for(mi);
        const idb::AsmCost ac =
            idb::cost(isa_, form, static_cast<uint32_t>(ua_id_));
        if (!ac.found) return generic_cost_for(mi); // la uarch no cronometra
        // Partir de la familia generica (para el fallback de grupos) y
        // sobreescribir con los numeros EXACTOS de la DB.
        InstrCost c = generic_cost_for(mi);
        c.latency = ac.latency > 0.0f ? ac.latency : c.latency;
        c.recip_tp = ac.recip_tp > 0.0f ? ac.recip_tp : c.recip_tp;
        c.uops = ac.uops > 0 ? static_cast<float>(ac.uops) : c.uops;
        // Grupos de puertos REALES de la microarquitectura para esta forma.
        if (ac.ports != nullptr && ac.ports_count > 0) {
            c.nports = 0;
            for (uint8_t i = 0; i < ac.ports_count && c.nports < kMaxSchedPorts;
                 ++i)
                c.ports[c.nports++] =
                    SchedPortUse{ac.ports[i].port, ac.ports[i].uops};
        }
        return c;
    }
    int issue_width() const override {
        // El ancho de emision del core ~ suma de capacidades de sus puertos,
        // acotado a un rango sensato (los cores modernos emiten 4-6
        // uops/ciclo).
        int total = 0;
        for (int g = 0; g < port_count(); ++g)
            total += port_capacity(g);
        if (total < 2) total = 2;
        if (total > 8) total = 8;
        return total;
    }
    int port_count() const override {
        return ua_ ? static_cast<int>(ua_->port_count) : 0;
    }
    int port_capacity(int group) const override {
        if (!ua_ || group < 0 || group >= static_cast<int>(ua_->port_count))
            return 1;
        return port_group_capacity(ua_->port_names[group]);
    }
    const char *port_name(int group) const override {
        if (!ua_ || group < 0 || group >= static_cast<int>(ua_->port_count))
            return "?";
        return ua_->port_names[group];
    }
    const char *name() const override { return name_.c_str(); }

  private:
    idb::Isa isa_;
    int32_t ua_id_;
    const idb::MicroarchData *ua_;
    std::string name_;
};

/// Devuelve el MicroarchData de @p ua_id en la ISA (o nullptr).
const idb::MicroarchData *uarch_data(idb::Isa isa, int32_t ua_id) {
    const idb::CostData &cd = (isa == idb::Isa::ARM64)   ? idb::cost_arm64()
                              : (isa == idb::Isa::ARM32) ? idb::cost_arm32()
                              : (isa == idb::Isa::RISCV) ? idb::cost_riscv()
                                                         : idb::cost_x86();
    if (ua_id < 0 || static_cast<uint32_t>(ua_id) >= cd.count) return nullptr;
    return &cd.uarchs[ua_id];
}

// ========================================================================
//  Deteccion del core del HOST (JIT auto): cpuid en x86, MIDR en arm64.
// ========================================================================

#if defined(VX_HOST_X86)
void host_cpuid(unsigned leaf, unsigned subleaf, unsigned regs[4]) {
#if defined(_MSC_VER)
    int r[4];
    __cpuidex(r, static_cast<int>(leaf), static_cast<int>(subleaf));
    regs[0] = r[0];
    regs[1] = r[1];
    regs[2] = r[2];
    regs[3] = r[3];
#else
    __get_cpuid_count(leaf, subleaf, &regs[0], &regs[1], &regs[2], &regs[3]);
#endif
}

/// Lee de CPUID lo que decide la microarquitectura, en el core que ejecuta esto.
HostCpuId read_host_cpuid() {
    HostCpuId id;
    unsigned r[4] = {0, 0, 0, 0};

    host_cpuid(0, 0, r);
    const unsigned max_leaf = r[0];
    char vendor[13] = {0};
    std::memcpy(vendor + 0, &r[1], 4); // EBX
    std::memcpy(vendor + 4, &r[3], 4); // EDX
    std::memcpy(vendor + 8, &r[2], 4); // ECX
    id.vendor = vendor;

    host_cpuid(1, 0, r);
    const unsigned base_family = (r[0] >> 8) & 0xF;
    const unsigned base_model = (r[0] >> 4) & 0xF;
    const unsigned ext_model = (r[0] >> 16) & 0xF;
    const unsigned ext_family = (r[0] >> 20) & 0xFF;
    id.family = base_family + ((base_family == 0xF) ? ext_family : 0);
    id.model =
        base_model +
        (((base_family == 0x6) || (base_family == 0xF)) ? (ext_model << 4) : 0);

    // Hibrida: hoja 7, subhoja 0, EDX bit 15.  Se pregunta antes que la 0x1A
    // porque es la que dice si la 0x1A significa algo.
    if (max_leaf >= 7) {
        host_cpuid(7, 0, r);
        id.hybrid = ((r[3] >> 15) & 1u) != 0;
    }
    // Clase del core: hoja 0x1A, EAX[31:24].  Se consulta las DOS condiciones
    // -- que la hoja exista Y que la pieza sea hibrida -- porque una hoja que no
    // existe no devuelve un error, devuelve los registros de OTRA hoja, y eso
    // daria una clase de core inventada con toda la pinta de ser buena.
    if (id.hybrid && max_leaf >= 0x1A) {
        host_cpuid(0x1A, 0, r);
        id.core_type = (r[0] >> 24) & 0xFFu;
    }
    return id;
}
#endif // VX_HOST_X86

} // namespace

// El mapeo va FUERA del namespace anonimo y fuera de la guarda de host: es una
// funcion PURA sobre lo que CPUID contesto, asi que se compila y se prueba en
// cualquier maquina, incluida una que no sea x86.  Leer CPUID es lo unico que
// depende de donde se corre, y eso se queda arriba.
std::string uarch_from_cpuid(const HostCpuId &id) {
    const unsigned family = id.family;
    const unsigned model = id.model;
    const bool intel = id.vendor == "GenuineIntel";
    const bool amd = id.vendor == "AuthenticAMD";

    if (intel && family == 0x6) {
        switch (model) {
        case 0x2A:
        case 0x2D: return "intel-sandybridge";
        case 0x3C:
        case 0x45:
        case 0x46:
        case 0x3F: return "intel-haswell";
        case 0x3D:
        case 0x47:
        case 0x4F:
        case 0x56: return "intel-broadwell";
        case 0x55: return "intel-skylake-x";
        case 0x4E:
        case 0x5E:
        case 0x8E:
        case 0x9E:
        case 0xA5:
        case 0xA6: return "intel-skylake";
        case 0x7D:
        case 0x7E:
        case 0x6A:
        case 0x6C: return "intel-icelake";
        case 0xA7: return "intel-rocketlake";
        // Alder Lake y Raptor Lake son HIBRIDAS: el mismo modelo describe un
        // core P y uno E, que no comparten latencias ni puertos.  La DB trae las
        // dos filas; elegir siempre la P costeaba con el modelo equivocado los
        // 8 cores E de un i7-13700KF de 24 hilos.
        case 0x97:
        case 0x9A:
        case 0xBF:
        case 0xB7:
        case 0xBA:
            return (id.core_type == CORE_TYPE_ATOM) ? "intel-alderlake-e"
                                                    : "intel-alderlake-p";
        default: return "intel-skylake"; // Intel moderno desconocido
        }
    }
    if (amd) {
        if (family == 0x17) return (model >= 0x30) ? "amd-zen2" : "amd-zen1";
        if (family == 0x19) return (model >= 0x40) ? "amd-zen4" : "amd-zen3";
        if (family >= 0x1A) return "amd-zen5";
        return "amd-zen3"; // AMD moderno desconocido
    }
    return ""; // vendor desconocido -> generico
}

namespace {

#if defined(VX_HOST_ARM64)
/// Nombre de microarquitectura arm64 del host via MIDR_EL1 (part number).
std::string host_uarch_arm64() {
    uint64_t midr = 0;
#if defined(__linux__)
    // MIDR_EL1 no es legible en EL0; usar el part number de getauxval si
    // esta, o /proc/cpuinfo.  Aproximacion por implementador+part.
    (void)midr;
#endif
    // Leer MIDR via inline-asm solo es legal en EL1; en EL0 devolveria SIGILL.
    // Mapeo minimo por si el runtime expone el part; si no, generico.
    return ""; // arm64 host: usar --cpu explicito o generico (seguro)
}
#endif

/// Nombre de microarquitectura del host para la ISA objetivo (JIT auto).  Solo
/// tiene sentido cuando la ISA objetivo == ISA del host (el JIT compila para el
/// host).  Devuelve "" si no se puede detectar -> generico.
std::string host_uarch_name(SchedIsa isa) {
#if defined(VX_HOST_X86)
    if (isa == SchedIsa::X86_64 || isa == SchedIsa::X86_32)
        return uarch_from_cpuid(read_host_cpuid());
#endif
#if defined(VX_HOST_ARM64)
    if (isa == SchedIsa::ARM64) return host_uarch_arm64();
#endif
    (void)isa;
    return "";
}

idb::Isa to_db_isa(SchedIsa isa) {
    return (isa == SchedIsa::ARM64) ? idb::Isa::ARM64 : idb::Isa::X86;
}

} // namespace

std::unique_ptr<SchedCostModel>
make_cost_model(SchedIsa isa, const std::string &cpu, SchedMode mode) {
    const idb::Isa dbi = to_db_isa(isa);

    // 1. --cpu explicito: microarquitectura exacta de la DB.
    if (!cpu.empty() && cpu != "generic") {
        const int32_t ua = idb::microarch_by_name(dbi, cpu);
        const idb::MicroarchData *md = uarch_data(dbi, ua);
        if (ua >= 0 && md != nullptr)
            return std::unique_ptr<SchedCostModel>(
                new UarchCostModel(dbi, ua, md, cpu));
        // uarch desconocida -> cae al generico (nunca null).
    }

    // 2. JIT: auto-detectar el core del HOST (isa objetivo == isa del host).
    if (mode == SchedMode::JIT_AUTO && cpu.empty()) {
        const std::string host = host_uarch_name(isa);
        if (!host.empty()) {
            const int32_t ua = idb::microarch_by_name(dbi, host);
            const idb::MicroarchData *md = uarch_data(dbi, ua);
            if (ua >= 0 && md != nullptr)
                return std::unique_ptr<SchedCostModel>(
                    new UarchCostModel(dbi, ua, md, host + " (host)"));
        }
    }

    // 3. AOT sin --cpu (o deteccion fallida): modelo generico portable.
    return std::unique_ptr<SchedCostModel>(new GenericCostModel());
}

namespace {
std::string g_sched_cpu; // --cpu global (fijado por main.cpp)
} // namespace

void set_sched_cpu(const std::string &cpu) {
    g_sched_cpu = cpu;
}
const std::string &sched_cpu() {
    return g_sched_cpu;
}

} // namespace sched
} // namespace jit
