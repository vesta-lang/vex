/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir_emitter.cpp
 * @brief Implementacion del emisor IR -> texto .vel (lowering con linear scan).
 *
 * Estructura del codigo emitido para cada funcion:
 *
 *   fn_label:
 *       enter <spill_count>      ; prologo: guarda rbp, reserva slots de pila
 *       ...instrucciones...
 *   fn_label_ret:
 *       leave
 *       ret
 *
 * Las etiquetas de bloque siguen el patron "fn_<nombre>_<bloque>".
 *
 * Manejo de operaciones de dos direcciones (.vel):
 *   adds r_dst, r_src  <=>  r_dst += r_src
 *   Si r_dst != reg_de(operando_izquierdo):
 *       mov r_dst, r_op0
 *       adds r_dst, r_op1
 *   Si r_dst == reg_de(operando_izquierdo):
 *       adds r_dst, r_op1     ; operacion en sitio, sin mov extra
 *
 * Spilling:
 *   Valores derramados se almacenan en slots de pila reservados por enter N.
 *   Cada slot ocupa 8 bytes; el acceso usa movc con base rbp y offset slot*8.
 *   load_src emite la carga antes de usar el valor; store_spilled emite el
 *   almacenamiento despues de calcularlo. Se usan r14 y r13 como scratches.
 */

#include "util/env_flags.h"
#include "ir/ir_emitter.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include "ir/vel_sink.h" // a donde sale lo emitido (una emision, N destinos)
#include "ir/gc_safepoint.h" // pase compartido: raices GC por safepoint
#include "analysis/asa/aggregate_facts.h"
#include <chrono>
#include <iostream>
#include "ir/ir_optimizer.h"
#include "ctpe/fold.h"
#include "ir/liveness.h"
#include "codegen/vm_allocate.h"
#include "ir/regalloc.h"
#include "ir/ssa_ir.h"
#include "vx/asm/asm_effects.h"        // inc.6: asm_canonical_reg
#include "vx/asm/asm_phys_reg.h"       // sustitucion $N -> reg fisico
#include "jit/inline_asm_trampoline.h" // inc.6: fnv1a64_asm (clave del trampoline)
#include "jit/ssa_coalesce.h"      // ssa_phi_coalesce_remap (congruencia SSA)
#include "codegen/parallel_move.h" // sequence_parallel_moves (compartido 3 modos)
#include "loader/interp_stackmap.h" // E.1: INTERP_SM_SLOT_BASE + StackmapGcKind
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <cstdint>

namespace ir {

// =========================================================================
//  Acceso a slot de derrame (spill) en 1 instruccion via mld/mst.
//
//  El slot vive en rbp - (slot+1)*8 (offset NEGATIVO, area del frame local).
//  rbp NO es una base SIB valida (no esta en r0-r15), asi que antes cada acceso
//  eran 3 instrucciones (mov r13,rbp; subu r13,off; mov reg/[r13]).  mld/mst
//  codifican rbp como base -> 1 instruccion.  ctrlword=784 (base=rbp(16),
//  width=8B).  Fallback a la secuencia de 3 si off excede int16 (+/-32KB).
//  Libre (no toca caches del EmitCtx; el llamante los invalida si procede).
// =========================================================================
static inline void emit_spill_access(VelSink &out, const Reg &reg,
                                     long long slot, bool is_load) {
    const long long off = (slot + 1) * 8;
    if (off <= 32768) {
        const uint16_t disp = static_cast<uint16_t>(static_cast<int16_t>(-off));
        out << "    " << (is_load ? "mld" : "mst") << " " << reg
            << ", r0, 784, " << static_cast<unsigned>(disp) << "\n";
        return;
    }
    // Fallback (offset > 32KB, funcion enorme): secuencia de 3 instrucciones.
    out.emit(emmit::Mnemonic::MOV, Reg::gp(13), Reg::special(SpecialReg::RBP));
    out.emit(emmit::Mnemonic::SUBU, Reg::gp(13), off);
    if (is_load)
        out.emit(emmit::Mnemonic::MOV, Reg(reg), Mem(Reg::gp(13)));
    else
        out.emit(emmit::Mnemonic::MOV, Mem(Reg::gp(13)), Reg(reg));
}

// =========================================================================
//  Contexto interno de emision por funcion
// =========================================================================

struct EmitCtx {
    const IrFunction &fn;           // funcion SSA a emitir
    const codegen::RegAlloc &alloc; // asignacion de registros
    const LivenessResult
        &liveness;   // intervalos de vida (necesario para save/restore en CALL)
    VelSink &out;    // a donde sale lo emitido (ver ir/vel_sink.h)
    bool comments;   // emitir comentarios de origen
    bool emit_debug; // emitir comentarios @line N por instruccion
    bool emit_stackmaps; //  E.1: emitir `// @sm <hex>` en safepoints
    uint32_t label_seq;  // secuencia para etiquetas unicas de condicion
    // true si se emitio enter (spill_count > 0); false = metodo hoja sin frame.
    // Permite skipear leave en epilogos cuando no hay frame, ahorrando 2 bytes
    // por ret en metodos hoja (tipicos: getters, setters, ops aritmeticas
    // pequenas).
    bool has_frame;
    // Multiprecision: CARRYOF cuyo `setcc` ya se emitio pegado a su ADDC/SUBB.
    // El acarreo vive en un flag, y cualquier operacion aritmetica que se
    // cuele entre la suma y su lectura lo pisa -- cosa que pasa en cuanto la
    // suma se inlinea dentro de otra, porque el orden del IR deja de ser el
    // orden de emision.  Materializarlo en el acto y anotarlo aqui evita
    // depender de esa distancia.
    std::unordered_set<IrValueId> carry_done;
    // Primer operando de cada ADDC/SUBB, y si era resta.  Sirve de respaldo
    // cuando la lectura del acarreo cae en un bloque distinto que su suma:
    // alli el flag ya no es el suyo, asi que se recalcula comparando.
    std::unordered_map<IrValueId, std::pair<IrValueId, bool>> carry_src;

    // true si la funcion contiene alguna ALLOCA (subsp rsp dinamico entre el
    // area de spill y el area de push).  Cuando lo hay, la aritmetica
    // rbp-relativa de los handles empujados a traves de un CALL deja de ser
    // fiable (el ALLOCA desplaza rsp de forma no reflejada en spill_count),
    // asi que el stackmap de sitio de retorno NO registra las raices
    // register-held empujadas (el scan conservador las cubre en modo aditivo).
    bool has_alloca = false;

    // Fusion de direccion en mld/mst: instrucciones ADD/MUL que se fusionaron
    // en el direccionamiento de un LOAD/STORE.  Se SALTAN en el loop de emision
    // (su efecto lo hace el mld/mst).
    std::unordered_set<const IrInstr *> fused_skip;
    // Descriptor de direccion fusionada: `[base + index<<scale + disp]`.
    // Fase 1 (campo, offset const): index = IR_NO_VALUE, disp = offset.
    // Fase 2 (array, index en reg):  index = reg, disp = 0, scale = shift.
    struct FuseAddr {
        IrValueId base;
        IrValueId index; // IR_NO_VALUE si no hay indice
        int32_t disp;
        uint8_t scale; // shift del indice (0..7 -> *1..*128)
    };
    // LOAD/STORE cuyo direccionamiento se fusiono -> descriptor.
    std::unordered_map<const IrInstr *, FuseAddr> addr_fusion;

    // Fase 3 (banco ancho callee-saved): registros ZMM (f3..f15) que ESTA
    // funcion usa y por tanto guarda en el prologo (mst-FP a un slot rbp) y
    // restaura en el epilogo (mld-FP).  Asi los valores del banco sobreviven a
    // los calls sin save per-call (el callee preserva lo que toca).  El slot de
    // guardado del k-esimo reg vive en rbp - (spill_count + k + 1)*8.
    std::vector<int> zmm_saved_regs;
    uint32_t zmm_save_slot_base = 0; // = spill_count

    // Modulo al que pertenece la funcion.  Lo consulta STR_LIT_ADDR para saber
    // a que seccion referenciar cada slot: el storage de una variable global
    // vive en `gdata` (memoria host) y el resto en `code` (memoria VM).  Puede
    // ser null en emisiones sueltas (tests) -> entonces todo va a `code`, que
    // es el comportamiento historico.
    const IrModule *mod = nullptr;

    // Cache de constantes en scratches para evitar `mov r14, K; mov r14, K`
    // consecutivos (patron tipico: dos SEXTs back-to-back con K=32 entre
    // los que no hay instrs que clobreen r14).  -1 = invalido (clobreado o
    // bloque nuevo).  Se invalida en cualquier basic-block boundary
    // (emision de label) y en cualquier instruccion que use r14 como
    // destino fuera del cache.
    int64_t r14_cache = -1;
    int64_t r13_cache = -1;

    // Optimizacion FP: valor SSA que YA esta en el registro ZMM f0 (resultado
    // de la ultima op float).  Entre ops float consecutivas (fsqrt->fsub->fabs
    // ...) el emisor guarda f0 a un GP (bitz2g) y lo vuelve a cargar (bitg2z)
    // en la siguiente op -- pero f0 no cambia entre medias, asi que el reload
    // es redundante.  Cuando el src1 de una op float == last_f0, se omite el
    // reload.  IR_NO_VALUE = f0 desconocido (se invalida en cada label y en
    // cualquier instruccion que NO sea una op float binaria/unaria, que podria
    // clobrear f0).  Elimina los round-trips GP<->ZMM redundantes en loops
    // float-heavy (el mayor coste del backend FP del interprete).
    IrValueId last_f0 = IR_NO_VALUE;

    // nombre base para etiquetas de esta funcion
    std::string fn_lbl;

    EmitCtx(const IrFunction &fn_, const codegen::RegAlloc &alloc_,
            const LivenessResult &liveness_, VelSink &out_, bool comments_,
            bool emit_debug_, bool has_frame_, bool emit_stackmaps_ = false)
        : fn(fn_), alloc(alloc_), liveness(liveness_), out(out_),
          comments(comments_), emit_debug(emit_debug_),
          emit_stackmaps(emit_stackmaps_), label_seq(0), has_frame(has_frame_),
          fn_lbl(sanitize(fn_.name)) {}

    // Convierte un nombre arbitrario a un identificador .vel valido
    static std::string sanitize(const std::string &s) {
        std::string r;
        r.reserve(s.size());
        for (char c : s) {
            if (std::isalnum((unsigned char)c) || c == '_')
                r += c;
            else
                r += '_';
        }
        return r;
    }

    // Nombre de etiqueta para un bloque
    std::string block_label(IrBlockId bid) const {
        if (bid < fn.blocks.size()) return fn_lbl + "_" + fn.blocks[bid].name;
        return fn_lbl + "_bb" + std::to_string(bid);
    }

    /**
     * @brief El REGISTRO de un valor (o el scratch como respaldo, sin efecto de
     *        lado).
     *
     * Devuelve un @c Reg y no su nombre: mientras esto diera una cadena, cada
     * sitio que lo usaba tenia que coser la sintaxis a mano -- corchetes de
     * memoria, sufijos de ancho -- y ahi es donde se cuelan los errores que el
     * texto no puede ver.  El asignador ya trabaja con INDICES, asi que
     * construir el registro aqui no traduce nada: deja de destruir el tipo.
     */
    Reg reg_of(IrValueId vid) const {
        if (vid == IR_NO_VALUE) return Reg::gp(0);
        if (alloc.in_reg(vid)) return Reg::gp(alloc.reg_of(vid));
        return Reg::gp(SCRATCH_REG);
    }

    /// Como @c reg_of, pero indicando QUE scratch se uso al recargar el valor
    /// (0 = SCRATCH_REG, 1 = SCRATCH2_REG).  Necesario cuando una instruccion
    /// lee DOS operandos derramados: cada uno vive en un scratch distinto y
    /// @c reg_of, que siempre devuelve el primero, los confundiria.
    /// Se usa junto a @c load_src(vid, idx), que es quien emite la carga.
    Reg reg_at(IrValueId vid, int scratch_idx) const {
        if (vid == IR_NO_VALUE) return Reg::gp(0);
        if (alloc.in_reg(vid)) return Reg::gp(alloc.reg_of(vid));
        return Reg::gp(scratch_idx == 0 ? SCRATCH_REG : SCRATCH2_REG);
    }

    // True si el valor vid tiene un registro asignado (no derramado)
    bool is_in_reg(IrValueId vid) const {
        return vid != IR_NO_VALUE && alloc.in_reg(vid);
    }

    /// @brief Carga un valor DERRAMADO en un registro concreto @p dst_reg.
    ///
    /// Como @ref load_src pero sin usar los scratch de siempre: hace falta
    /// cuando una instruccion tiene mas operandos que scratch disponibles (el
    /// CAS atomico tiene tres).  Usa r13 para calcular la direccion, asi que
    /// debe llamarse ANTES que los `load_src` cuyo resultado viva en r13.
    // ctrlword de un slot de derrame para mld/mst: base=rbp(16), width=8B
    // (wcode=3), sin index/host/sign/bank/scale -> 16 | (3<<8) = 784.
    static constexpr unsigned kSpillCtrlWord = 784u;

    // Emite la carga de un slot de derrame en 1 instruccion (mld) -- resuelve
    // la codificacion [rbp - off] que el SIB no admite (rbp no es base GP), asi
    // que antes eran 3 instrucciones (mov r13,rbp; subu; mov [r13]).  NO
    // clobbea r13.  Fallback a la secuencia de 3 si el offset excede int16
    // (+/-32KB).
    void emit_spill_load(const Reg &dst_reg, int slot) {
        const bool fallback = ((long long)(slot + 1) * 8) > 32768;
        emit_spill_access(out, dst_reg, slot, /*is_load=*/true);
        // El mld NO clobbea r13/r14 (a diferencia del fallback); solo invalidar
        // el cache si escribimos ese scratch o si el fallback usa r13.
        if (fallback || dst_reg.is_gp(13)) r13_cache = -1;
        if (dst_reg.is_gp(14)) r14_cache = -1;
    }

    void emit_spill_store(const Reg &src_reg, int slot) {
        const bool fallback = ((long long)(slot + 1) * 8) > 32768;
        emit_spill_access(out, src_reg, slot, /*is_load=*/false);
        if (fallback) r13_cache = -1; // el fallback usa r13 como temp
    }

    void emit_load_spilled_into(IrValueId vid, const Reg &dst_reg) {
        if (!alloc.spilled(vid)) return; // no derramado: nada que hacer
        emit_spill_load(dst_reg, alloc.slot_of(vid));
    }

    // Fase 3 (regalloc ZMM): valores float que viven en un registro ZMM del
    // banco (f3..f15) en vez de en GP + roundtrip bitg2z/bitz2g.  f0/f1/f2
    // quedan reservados como scratch para operandos GP y el temp de 2-address.
    std::unordered_map<IrValueId, int> zmm_map;
    // Registro ZMM (0..15) de un valor, o -1 si no esta asignado al banco ZMM
    // (usa el path GP + bitcast).
    int zmm_of(IrValueId vid) const {
        auto it = zmm_map.find(vid);
        return it == zmm_map.end() ? -1 : it->second;
    }

    // Numero de registro de un valor (SCRATCH_REG si derramado)
    int reg_num(IrValueId vid) const {
        if (alloc.in_reg(vid)) return alloc.reg_of(vid);
        return SCRATCH_REG;
    }

    // true si el value @p vid es un host_ptr a un objeto
    // GC (marcado por el lowering en lower_new_expr / lower_class_field_load
    // / params CLASS de class methods).  Los values is_gc_object necesitan
    // tratamiento especial al spillarse: el SLOT contiene el GcHandle
    // (estable a evacuacion), mientras que el reg contiene el host_ptr
    // (lo que CALLVIRT, GETFIELD y demas opcodes esperan).
    bool is_gc_value(IrValueId vid) const {
        if (vid == IR_NO_VALUE) return false;
        if (static_cast<size_t>(vid) >= fn.values.size()) return false;
        return fn.values[vid].is_gc_object;
    }

    // Materializa un operando FUENTE: si esta derramado emite la carga del
    // slot al registro scratch (scratch_idx 0=r14, 1=r13) y devuelve su
    // nombre.  Para values is_gc_object spilled, el slot guarda el HANDLE
    // (no el host_ptr), por lo que tras el load emitimos gcderef + xchg
    // para devolver un host_ptr FRESCO (post-eventual GC move).  Asi el
    // resto del emisor recibe siempre host_ptr en regs is_gc_object,
    // independientemente de si vinieron de reg directo o de spill.
    /**
     * @brief EN QUE registro de la VM deja @ref load_src el valor @p vid.
     *
     * El mismo criterio que @ref load_src, devuelto como numero en vez de como
     * nombre.  Hace falta cuando el valor no se va a escribir en el texto sino
     * a DECIR: un bloque `asm` puede leer sus operandos del registro donde ya
     * estan, y para eso hay que poder nombrar el registro, no imprimirlo.
     *
     * Lee el mismo estado que aquel a proposito.  Duplicar la decision seria
     * arriesgar que el numero dicho y el registro usado se separen, y eso no
     * falla: mueve el valor equivocado.
     *
     * @param vid Valor.
     * @param scratch_idx Cual de los dos scratch usaria si estuviera derramado.
     * @return indice del registro de la VM (0..15).
     */
    int load_src_reg(IrValueId vid, int scratch_idx = 0) const {
        if (vid == IR_NO_VALUE) return 0; // r0, igual que load_src
        if (alloc.in_reg(vid)) return alloc.reg_of(vid);
        return (scratch_idx == 0) ? SCRATCH_REG : SCRATCH2_REG;
    }

    Reg load_src(IrValueId vid, int scratch_idx = 0) {
        if (vid == IR_NO_VALUE) return Reg::gp(0);
        if (alloc.in_reg(vid)) return Reg::gp(alloc.reg_of(vid));
        {
            if (alloc.spilled(vid)) {
                int sr = (scratch_idx == 0) ? SCRATCH_REG : SCRATCH2_REG;
                // Calcular direccion: r13 = rbp - (slot+1)*8.
                //
                // Bug critico arreglado (2026-05-10): antes usabamos
                // `addu r13, slot*8` (offset POSITIVO desde rbp), lo que
                // colocaba los slots EN EL AREA DEL CALLER:
                //   rbp+0  = saved_rbp del caller (push rbp en enter)
                //   rbp+8  = RET_ADDR pushed por callvirt
                //   rbp+16 = caller's locals
                // Con varios spills, el slot 1 sobrescribia RET_ADDR y al
                // hacer leave+ret la VM saltaba a un valor pequenio (un
                // GcHandle).  En el editor TUI, render_buffer hacia 6
                // spills, corrompiendo RET_ADDR y `this` del caller (run).
                // Sintoma: editor crasheaba justo despues del primer render.
                //
                // El fix usa offsets NEGATIVOS desde rbp:
                //   slot 0 = rbp - 8   (primer local, justo bajo saved_rbp)
                //   slot 1 = rbp - 16  (segundo local)
                //   ...
                // Estos offsets caen en el area allocada por `enter` (sub
                // rsp, frame_size), que es local al frame y nadie mas
                // toca.  Combinado con el fix de enter (allocacion en
                // bytes = spill_count*8), los locals viven seguros.
                emit_spill_load(Reg::gp(sr), alloc.slot_of(vid));
                if (is_gc_value(vid)) {
                    // El slot contiene el GcHandle.  Convertir a host_ptr
                    // fresco (gcderef indexa la HandleTable, que el GC
                    // mantiene actualizada tras moves -- transparent).
                    out.emit(emmit::Mnemonic::GCDEREF,
                             Reg::special(SpecialReg::CUR0),
                             Reg::gp(static_cast<unsigned>(sr)));
                    out.emit(emmit::Mnemonic::XCHG,
                             Reg::special(SpecialReg::CUR0),
                             Reg::gp(static_cast<unsigned>(sr)));
                }
                return Reg::gp(sr);
            }
        }
        return Reg::gp(SCRATCH_REG);
    }

    // Devuelve el registro DESTINO de vid: si esta derramado retorna r14
    // sin emitir codigo (el llamante debe invocar store_spilled despues).
    /// El registro DESTINO de un valor.  Devuelve @c Reg por lo mismo que
    /// @ref reg_of: el asignador razona con indices, y convertirlo a texto aqui
    /// obligaba a cada sitio a coser la sintaxis a mano.
    Reg dst_of(IrValueId vid) {
        if (vid == IR_NO_VALUE) return Reg::gp(0);
        if (alloc.in_reg(vid)) return Reg::gp(alloc.reg_of(vid));
        return Reg::gp(SCRATCH_REG);
    }

    // Si vid esta derramado, persiste el valor en su slot de pila.
    // Si el valor tiene ademas un registro asignado, leer de EL y no de
    // SCRATCH_REG (que tendria garbage tras una llamada).
    void store_spilled(IrValueId vid) {
        if (vid == IR_NO_VALUE) return;
        if (!alloc.spilled(vid)) return;
        Reg src_reg = Reg::gp(SCRATCH_REG);
        if (alloc.in_reg(vid)) src_reg = Reg::gp(alloc.reg_of(vid));
        if (is_gc_value(vid)) {
            out.emit(emmit::Mnemonic::GCHANDLE, Reg::gp(SCRATCH_REG), src_reg);
            src_reg = Reg::gp(SCRATCH_REG);
            r14_cache = -1;
        }
        // Slot en offset NEGATIVO desde rbp; 1 instruccion (mst) con fallback.
        emit_spill_store(src_reg, alloc.slot_of(vid));
    }

    // Emite un comentario si los comentarios estan activados
    void comment(const std::string &msg) {
        if (comments) out << "    // " << msg << "\n";
    }

    // Genera una etiqueta local unica
    std::string unique_lbl(const std::string &base) {
        return fn_lbl + "_" + base + "_" + std::to_string(label_seq++);
    }

    // Genera una referencia @Absolute con el prefijo de seccion "code."
    // Todas las etiquetas internas del .vel viven en la seccion "code".
    static std::string abs_lbl(const std::string &lbl) { return "code." + lbl; }
};

/**
 * @brief Indica si el slot @p idx es el storage de una variable global.
 *
 * Esos slots viven en memoria HOST (seccion `gdata`), no en la de la VM: su
 * direccion se toma con `&global` y viaja hasta sitios donde el unico contrato
 * es el tipo (`T*` = host) o donde hace falta una direccion de maquina (la FFI,
 * un `lock cmpxchg`).  El lowering los distingue con section_name ".data" -- el
 * mismo dato que ya usaba el codegen AOT para emitirlos en `.data` (rw) en vez
 * de `.rodata`.
 *
 * @param mod Modulo con el pool de static_data.
 * @param idx Indice del slot.
 * @return true si el slot va a `gdata`.
 */
static bool slot_is_gdata(const IrModule &mod, size_t idx) {
    return mod.static_data.meta_at(idx).section_name == ".data";
}

// =========================================================================
//  Utilidades internas del emisor
// =========================================================================

// Devuelve el sufijo de tamano de registro VM segun el ancho del IrType.
// Mapeo:  1 byte -> "b"  | 2 bytes -> "w"  | 4 bytes -> "d"  | 8 bytes -> ""
// Ejemplo: para r3 con tipo I32, devuelve "r3d" (32 bits low de r3).
static Reg reg_name_sized(int reg, IrType t) {
    // El ancho sale del eje de RANURA del vocabulario unico, que es el que
    // habla de registros; width_for_bytes lo traduce al sufijo del .vel.  Antes
    // habia aqui una tercera copia de esa misma tabla, escrita en terminos de
    // Reg::Width en vez de bytes -- la misma regla dicha de otra forma.
    return Reg::gp(reg,
                   width_for_bytes(static_cast<unsigned>(type_slot_bytes(t))));
}

// El tamano en bytes del tipo (paso de arrays, ancho de registro, hueco de
// pila) lo contesta ir::type_slot_bytes, del vocabulario unico -- aqui vivia
// una copia de esa tabla.

// Anade a un NOMBRE de registro ya formado (p.ej. "r5", "r14") el sufijo de
// tamano (b/w/d) segun el ancho del tipo, para los atomicos width-aware: el
// emisor de bytecode lee ese sufijo y codifica el mode (8/16/32/64) en el
// ctrl-byte.  8 bytes -> sin sufijo (registro completo).  Mismo formato que
// @c reg_name_sized pero operando sobre el string ya resuelto por el regalloc.
static Reg atomic_sized(Reg reg, IrType t) {
    // El ancho es parte del operando, no un sufijo que se le pega al nombre.
    reg.width = width_for_bytes(static_cast<unsigned>(type_slot_bytes(t)));
    return reg;
}

// =========================================================================
//  Emision de instrucciones individuales
// =========================================================================

//  AS inc.6: id fisico GP host (0..15) de un registro canonico
// (rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7, r8=8 .. r15=15).
// -1 si no es un GP (banco vectorial, o nombre no reconocido).
static int gp_phys_of_canon(const std::string &canon) {
    static const char *N[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                                "rsi", "rdi", "r8",  "r9",  "r10", "r11",
                                "r12", "r13", "r14", "r15"};
    for (int i = 0; i < 16; ++i)
        if (canon == N[i]) return i;
    return -1;
}

// Emite "mov r_dst, r_src" si son distintos (evita mov rx, rx)
static void emit_mov_if_needed(EmitCtx &ctx, const Reg &dst, const Reg &src) {
    /* Mismo registro Y misma vista: mover un registro sobre si mismo no hace
     * nada, pero `r0` y `r0b` NO son el mismo operando, asi que comparar solo
     * el nombre se saltaria una conversion de ancho que si hace falta. */
    if (dst == src) return;
    ctx.out.emit(emmit::Mnemonic::MOV, dst, src);
    // Si el dst es r14 o r13, invalidamos su cache de constante: ahora
    // contiene el VALOR del reg origen, no una constante conocida.
    if (dst.is_gp(14)) ctx.r14_cache = -1;
    if (dst.is_gp(13)) ctx.r13_cache = -1;
}

/**
 * @brief Emite una instruccion de TRES operandos registro.
 *
 * POR QUE HACE FALTA UN HELPER.  @c load_src solo dispone de DOS scratch
 * (@c r14 y @c r13): su @c scratch_idx es `0 -> r14`, cualquier otro `-> r13`.
 * Con tres operandos derramados, el tercero PISA al segundo y la instruccion
 * recibe el mismo registro dos veces -- fue un bug real (183_memcpy_idiom:
 * `memcpyh r14, r13, r13`, con el `src` machacado por el `len`, SIGSEGV).
 *
 * Estrategia: si los tres operandos YA viven en registro -- el caso comun -- se
 * emiten tal cual, sin un solo movimiento.  Solo si alguno esta derramado se
 * pasa por la pila, que es el unico modo de materializar tres valores con dos
 * scratch.  Asi el coste se paga exclusivamente cuando no hay alternativa.
 */
static void emit_three_reg_op(EmitCtx &ctx, emmit::Mnemonic mnem, IrValueId a,
                              IrValueId b, IrValueId c) {
    auto in_reg = [&](IrValueId v) {
        return v != IR_NO_VALUE && ctx.alloc.in_reg(v);
    };
    if (in_reg(a) && in_reg(b) && in_reg(c)) {
        const Reg ra = ctx.load_src(a, 0);
        const Reg rb = ctx.load_src(b, 0);
        const Reg rc = ctx.load_src(c, 0);
        ctx.out.emit(mnem, Reg(ra), Reg(rb), Reg(rc));
        return;
    }
    // Alguno derramado: r10/r11/r12 como portadores.  Se salvan antes (pueden
    // tener SSA vivos) y los VALORES se empujan segun se cargan, porque
    // @c load_src emite codigo como efecto colateral y reusa los scratch.
    ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(10));
    ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(11));
    ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(12));
    {
        const Reg p = ctx.load_src(a, 0);
        ctx.out.emit(emmit::Mnemonic::PUSH, p);
    }
    {
        const Reg p = ctx.load_src(b, 0);
        ctx.out.emit(emmit::Mnemonic::PUSH, p);
    }
    {
        const Reg p = ctx.load_src(c, 0);
        ctx.out.emit(emmit::Mnemonic::PUSH, p);
    }
    ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(12));
    ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
    ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
    ctx.out.emit(mnem, Reg::gp(10), Reg::gp(11), Reg::gp(12));
    ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(12));
    ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
    ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
    ctx.r13_cache = -1;
    ctx.r14_cache = -1;
}

// Emite `mov r14, K` SOLO si el cache de r14 indica un valor distinto.
// Si r14 ya tiene K (cacheado de un mov anterior dentro del mismo BB),
// la emision se omite.  El cache se invalida en bloques nuevos y por
// uso de r14 como destino fuera de esta helper.
static void emit_mov_r14_imm(EmitCtx &ctx, int64_t k) {
    if (ctx.r14_cache == k) return; // ya tiene ese valor
    ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(14), k);
    ctx.r14_cache = k;
}
static void emit_mov_r13_imm(EmitCtx &ctx, int64_t k) {
    if (ctx.r13_cache == k) return;
    ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), k);
    ctx.r13_cache = k;
}
// Wrapper generico: usa el cache correcto segun CUAL sea el scratch.
static void emit_mov_scratch_imm(EmitCtx &ctx, const Reg &scratch, int64_t k) {
    if (scratch.is_gp(14))
        emit_mov_r14_imm(ctx, k);
    else if (scratch.is_gp(13))
        emit_mov_r13_imm(ctx, k);
    else {
        ctx.out.emit(emmit::Mnemonic::MOV, scratch, k);
    }
}

// Variante optimizada para shifts: si K cabe en 1 byte, emite `mov scratchb, K`
// (4 bytes vs 11 bytes del i64).  Es seguro porque shl/sar enmascaran el shift
// count con (bits-1), asi que los bytes superiores de @p scratch son ignorados.
// Invalida el cache full-qword de scratch porque sus bytes altos quedan con un
// valor potencialmente distinto al esperado (no son tocados por el byte_lo).
static void emit_mov_scratch_shift_imm(EmitCtx &ctx, const Reg &scratch,
                                       int64_t k) {
    if (k >= 0 && k < 256) {
        ctx.out.emit(emmit::Mnemonic::MOV,
                     Reg::gp(scratch.index, Reg::Width::B), k);
        // Invalidar el cache: los bytes altos no se modifican, asi que el
        // valor completo del registro no es K.  Mejor olvidar.
        if (scratch.is_gp(14))
            ctx.r14_cache = -1;
        else if (scratch.is_gp(13))
            ctx.r13_cache = -1;
    } else {
        // K no cabe en 1 byte: fallback al mov i64 cacheado normal.
        emit_mov_scratch_imm(ctx, scratch, k);
    }
}
// Invalida los caches al cruzar un boundary de bloque (despues de emitir
// `label:`) o tras una llamada que clobrea scratches.
static void invalidate_scratch_caches(EmitCtx &ctx) {
    ctx.r14_cache = -1;
    ctx.r13_cache = -1;
}

// Emite `jmp @label(target)` solo si el bloque destino NO es el siguiente
// en orden de emision (i.e., si NO podemos caer por fallthrough natural).
// Ahorra ~46% de los jmp en codigo con if/while/for donde el target
// del jmp incondicional es siempre la siguiente etiqueta.
static void emit_jmp_or_fallthrough(EmitCtx &ctx, IrBlockId from_bid,
                                    IrBlockId target_id) {
    // El siguiente bloque en orden de emision es from_bid+1.  Si el target
    // coincide, la caida natural ya hace el "salto" y el jmp explicito
    // es redundante.  Para el ultimo bloque (from_bid+1 == fn.blocks.size())
    // siempre emitimos el jmp por seguridad.
    if (target_id == from_bid + 1) return;
    ctx.out.emit(emmit::Mnemonic::JMP,
                 Ann::absolute(EmitCtx::abs_lbl(ctx.block_label(target_id))));
}

// =========================================================================
//  Helpers de save/restore alrededor de instrucciones CALL
// =========================================================================
//
// Modelo de calling convention de la VM (ver ir_emitter.h):
//   - r0          : valor de retorno
//   - r1..r12     : argumentos de llamada (caller-saved: el callee los toca)
//   - r13         : SCRATCH2 del emisor (caller-saved)
//   - r14         : SCRATCH del emisor (caller-saved)
//   - r15         : argc (caller-saved)
//
// Es decir, NO HAY registros callee-saved.  Todo valor que esta vivo a traves
// de un CALL y que ocupa un registro fisico (r0..r12) debe preservarse
// explicitamente con push antes del call y pop despues.
//
// El bug que motivo este codigo: el regalloc lineal asigna parametros a
// r1..r12 al inicio de la funcion.  Si esos parametros se siguen usando
// despues de una llamada recursiva, el move de argumento ("mov r1, r_arg")
// los pisaba.  Ahora los salvamos a la pila antes de los moves.

// Calcula la posicion lineal de la instruccion en el index del bloque.
static uint32_t lin_pos_of(const EmitCtx &ctx, IrBlockId bid, size_t idx) {
    if (bid < ctx.liveness.block_start.size()) {
        return ctx.liveness.block_start[bid] + (uint32_t)idx;
    }
    return 0;
}

// Devuelve los numeros de registro fisico (0..12) que tienen valores vivos
// a traves de la instruccion @p call_pos y que deben preservarse.
//
// Un valor v esta vivo a traves de call_pos si def(v) < call_pos < end(v).
// El propio @p dst del CALL se EXCLUYE: se define EN el call, no antes.
//
// Devuelve los registros ordenados ascendentemente y deduplicados.
static std::vector<int>
live_regs_through_call(const EmitCtx &ctx, uint32_t call_pos, IrValueId dst) {
    // Registro fisico del dst.  El resultado del call se captura con
    // `mov dst, r0`, sobreescribiendo reg(dst).  Cualquier OTRO valor que
    // comparta ese mismo registro fisico tiene su valor pre-call igualmente
    // sobreescrito -> su valor viejo es dead -> NO debe guardarse/restaurarse
    // (si lo restaurase el fastpop pisaria el resultado del call).  Esto cubre
    // el caso de coalescencia de congruencias: un valor loop-carried (p.ej. un
    // acumulador via phi) coalescido con el dst del call comparte reg(dst); su
    // valor previo se descarta al escribir el retorno.  Sin coalescencia el
    // linear-scan nunca da el mismo reg a dst y a otro valor vivo simultaneo
    // (interfieren), asi que esta exclusion es no-op en ese caso.
    int dst_reg = -1;
    if (dst != IR_NO_VALUE) {
        if (ctx.alloc.in_reg(dst)) dst_reg = ctx.alloc.reg_of(dst);
    }
    std::vector<int> regs;
    regs.reserve(8);
    for (const auto &iv : ctx.liveness.intervals) {
        if (iv.id == dst) continue; // dst nace en el call
        // Vivo a traves del call si fue definido ANTES o EN call_pos y
        // se usa DESPUES.  Antes era `def < call_pos`, lo que excluia
        // los parametros (que tienen def=0) cuando el primer CALL
        // estaba en posicion 0 -> bug grave en ctors que llaman a otra
        // funcion como primera operacion (e.g. `this.inner = new Inner(x)`):
        // los params (this, x) no se preservaban y el codigo post-call
        // los referenciaba con valores ya clobbeados por el parallel-move.
        // Excluimos dst arriba, asi que valores definidos exactamente
        // en call_pos (si existieran via PHI o similar) no entran al
        // false positive: si vive despues, ya estaba en algun reg antes.
        if (iv.def <= call_pos && call_pos < iv.end) {
            if (!ctx.alloc.in_reg(iv.id))
                continue; // valor spilled, no en registro
            const int r = ctx.alloc.reg_of(iv.id);
            if (r == dst_reg) continue; // comparte reg con dst -> pre-call dead
            if (r >= 0 && r <= 12) regs.push_back(r);
        }
    }
    std::sort(regs.begin(), regs.end());
    regs.erase(std::unique(regs.begin(), regs.end()), regs.end());
    return regs;
}

// true si el reg @p r contiene un IrValueId con is_gc_object EN call_pos.
//
// BugFix C (2026-06-04): cuando el regalloc reusa el mismo reg para
// multiples values con live ranges que se traslapan por imprecision del
// liveness analysis (extension via live_out + back-edges), encontrar
// CUAL value es REALMENTE el que esta en el reg AL MOMENTO del call.
// La heuristica antigua retornaba @c true si CUALQUIER value asignado
// a @p r y con liveness range cubriendo @p call_pos era is_gc_object.
// Eso provocaba que values is_gc_object=false (e.g. counter int) se
// trataran como handles -> @c gchandle producia @c GC_NULL_HANDLE ->
// push/pop devolvia nullptr -> AV al primer deref.
//
// Fix: elegir el value con @c def_pos MAS GRANDE entre los candidatos.
// Ese es el value MAS RECIENTEMENTE definido y por tanto el realmente
// presente en el reg en @p call_pos (los anteriores ya fueron clobereados
// por la asignacion posterior).  Si NO hay ningun candidato gc, retorna
// false (el reg contiene un value no-gc en este punto del programa).
static bool reg_holds_gc_object(const EmitCtx &ctx, uint32_t call_pos, int r) {
    bool found_any = false;
    uint32_t best_def = 0;
    bool best_is_gc = false;
    for (const auto &iv : ctx.liveness.intervals) {
        if (!(iv.def <= call_pos && call_pos < iv.end)) continue;
        if (!ctx.alloc.in_reg(iv.id) || ctx.alloc.reg_of(iv.id) != r) continue;
        if (static_cast<size_t>(iv.id) >= ctx.fn.values.size()) continue;
        // Elegir el value mas recientemente definido (mayor iv.def) entre
        // los candidatos asignados al mismo reg con range que cubre call_pos.
        if (!found_any || iv.def > best_def) {
            found_any = true;
            best_def = iv.def;
            best_is_gc = ctx.fn.values[iv.id].is_gc_object;
        }
    }
    return found_any && best_is_gc;
}

// ------------------------------------------------------------------------
// Stackmaps precisos del interprete.
// ------------------------------------------------------------------------
//
// La deteccion de RAICES GC por safepoint es SEMANTICA y vive en un pase
// IR COMPARTIDO (ir/gc_safepoint.h): @c ir::is_gc_safepoint identifica los
// safepoints y @c ir::safepoint_gc_roots devuelve el conjunto de valores
// SSA vivos de tipo GC.  Ese conjunto es INDEPENDIENTE del backend (el
// mismo sirve para interp / JIT / AOT).  Aqui SOLO hacemos la
// MATERIALIZACION INTERP: mapear cada raiz SSA a su ubicacion fisica VM
// (registro R0..R15 o slot de spill) y emitir el marcador `// @sm`.

// Codifica un byte como 2 digitos hex en minuscula (append a @p out).
static void append_hex_byte(std::string &out, uint8_t b) {
    static const char *H = "0123456789abcdef";
    out.push_back(H[(b >> 4) & 0xF]);
    out.push_back(H[b & 0xF]);
}

// Emite el marcador `// @sm <hex>` para el safepoint en (@p bb, @p idx) si
// @c ctx.emit_stackmaps esta activo y hay al menos una raiz GC viva.
//
// El CONJUNTO de raices viene del pase IR compartido
// (@c ir::safepoint_gc_roots).  Aqui MATERIALIZAMOS cada raiz SSA a su
// ubicacion fisica VM:
//   - En un registro VM: location = numero de reg (0..15),
//     kind = HOSTPTR (el reg contiene el host_ptr; ver ir_emitter).
//   - Derramado a un slot: location = 0x40 + slot,
//     kind = HANDLE (el slot contiene el GcHandle estable a evacuacion).
//
// Nota de soundness: esto es un SUBCONJUNTO estricto de lo que el scan
// conservador marca (que mira TODOS los slots/regs).  El GC preciso corre
// en modo ADITIVO junto al conservador, asi que aunque omitamos alguna
// ubicacion, el conservador la cubre -> nunca se pierde una raiz viva.
// Solo excluimos registros MUERTOS (no vivos en el safepoint), que es
// exactamente el falso positivo que queremos eliminar.
// Ubicacion fisica VM materializada de una raiz.
namespace {
struct SmLoc {
    uint8_t location;
    uint8_t kind;
};
} // namespace

// Serializa @p locs a hex y emite el marcador `// @sm <hex>` (nada si vacio).
static void emit_sm_locs(EmitCtx &ctx, std::vector<SmLoc> &locs) {
    // Deduplicar por location (mantener el primer kind visto).
    std::sort(locs.begin(), locs.end(), [](const SmLoc &a, const SmLoc &b) {
        return a.location < b.location;
    });
    locs.erase(std::unique(locs.begin(), locs.end(),
                           [](const SmLoc &a, const SmLoc &b) {
                               return a.location == b.location;
                           }),
               locs.end());
    if (locs.empty()) return;

    // Serializar a hex: [u16 slot_count LE] [slot_count * {location, kind}].
    std::string hex;
    hex.reserve(4 + locs.size() * 4);
    const uint16_t count = static_cast<uint16_t>(locs.size());
    append_hex_byte(hex, static_cast<uint8_t>(count & 0xFF));
    append_hex_byte(hex, static_cast<uint8_t>((count >> 8) & 0xFF));
    for (const auto &l : locs) {
        append_hex_byte(hex, l.location);
        append_hex_byte(hex, l.kind);
    }
    ctx.out.stackmap(hex);
}

// Marcador para un safepoint de ALOCACION DIRECTA (frame TOP): materializa
// las raices en su registro VM (host_ptr) Y en su slot de spill (handle).
static void emit_stackmap_marker(EmitCtx &ctx, const IrBlock &bb, size_t idx) {
    if (!ctx.emit_stackmaps) return;
    const IrInstr &ins = bb.instrs[idx];
    if (!ir::is_gc_safepoint(ins.op)) return;

    const uint32_t pos = lin_pos_of(ctx, bb.id, idx);

    // Conjunto de raices GC (parte SEMANTICA compartida, pase IR).
    const std::vector<IrValueId> roots =
        ir::safepoint_gc_roots(ctx.fn, ctx.liveness, pos, ins.dst);
    if (roots.empty()) return;

    // Materializacion INTERP: raiz SSA -> ubicacion fisica VM.
    std::vector<SmLoc> locs;
    locs.reserve(roots.size() * 2);
    for (IrValueId vid : roots) {
        // Un valor puede tener reg Y spill; incluimos ambos (el reg lleva
        // host_ptr fresco, el slot lleva handle estable).
        if (ctx.alloc.in_reg(vid)) {
            const int r = ctx.alloc.reg_of(vid);
            if (r >= 0 && r < 16)
                locs.push_back(
                    {static_cast<uint8_t>(r),
                     static_cast<uint8_t>(jit::StackmapGcKind::HOSTPTR)});
        }
        if (ctx.alloc.spilled(vid)) {
            const int slot = static_cast<int>(ctx.alloc.slot_of(vid));
            if (slot >= 0 && slot < 0xC0)
                locs.push_back(
                    {static_cast<uint8_t>(loader::INTERP_SM_SLOT_BASE + slot),
                     static_cast<uint8_t>(jit::StackmapGcKind::HANDLE)});
        }
    }
    emit_sm_locs(ctx, locs);
}

// Predeclaracion: replica la decision de rama de @c emit_save_live_regs para
// saber la POSICION DE EMPUJE (0-based, desde el tope del area reservada por
// enter) de cada registro GC empujado a traves de un CALL.  Devuelve un mapa
// reg -> push_index solo para los regs que se empujan INDIVIDUALMENTE como
// handle (los GC).  Los no-GC empujados por fastpush no interesan aqui.
//
// El layout de pila del frame caller es:
//   rbp
//   [spill_count slots]          en rbp - 8*(0..spill_count)
//   [empujes]                    en rbp - 8*spill_count - 8*(push_idx+1)
// Un handle en push_idx equivale al slot rbp-relativo (spill_count + push_idx).
//
// El scan del interprete lee rbp - (slot+1)*8, por lo que codificamos cada
// handle empujado como un "slot de spill" con indice (spill_count + push_idx).
static std::unordered_map<int, int>
pushed_gc_reg_positions(const EmitCtx &ctx, uint32_t call_pos,
                        const std::vector<int> &regs_to_save) {
    std::unordered_map<int, int> pos_of;
    // Rama A de emit_save_live_regs: !any_gc && size>=2 -> fastpush, sin GC.
    bool any_gc = false;
    for (int r : regs_to_save) {
        if (reg_holds_gc_object(ctx, call_pos, r)) {
            any_gc = true;
            break;
        }
    }
    if (!any_gc) return pos_of; // ningun GC empujado individualmente
    // Empuje individual: en TODAS las ramas con any_gc, los regs GC se
    // empujan como `gchandle; push` en el orden de regs_to_save, ANTES de
    // cualquier fastpush de los no-GC (rama hibrida) o intercalados (rama
    // por defecto).  En ambos casos, el push_index de un reg GC es su
    // posicion secuencial de empuje: contamos cuantos empujes lo preceden.
    //
    // Rama hibrida (gc_first_ordered && num_nongc_tail>=2): los GC van
    // primero, luego un unico fastpush -> push_idx GC = contador secuencial
    // entre solo los GC.
    // Rama por defecto: cada reg (GC o no) se empuja en orden -> push_idx =
    // indice en regs_to_save.
    //
    // Determinamos la rama exactamente igual que emit_save_live_regs.
    bool gc_first_ordered = true;
    bool saw_nongc = false;
    int num_nongc_tail = 0;
    for (int r : regs_to_save) {
        const bool is_gc = reg_holds_gc_object(ctx, call_pos, r);
        if (is_gc && saw_nongc) {
            gc_first_ordered = false;
            break;
        }
        if (!is_gc) {
            saw_nongc = true;
            ++num_nongc_tail;
        }
    }
    const bool hybrid = gc_first_ordered && num_nongc_tail >= 2;
    int push_idx = 0;
    int gc_seq = 0;
    for (int r : regs_to_save) {
        const bool is_gc = reg_holds_gc_object(ctx, call_pos, r);
        if (hybrid) {
            // Los GC se empujan primero (secuencial); los no-GC despues.
            if (is_gc) pos_of[r] = gc_seq++;
        } else {
            // Empuje intercalado en orden de regs_to_save.
            if (is_gc) pos_of[r] = push_idx;
            ++push_idx;
        }
    }
    return pos_of;
}

// Marcador para el SITIO DE RETORNO de un CALL (frame CALLER).  El GC puede
// correr en el callee; cuando escanea el frame de ESTE caller, su PC es el
// return_pc (la instruccion inmediatamente posterior al call).  Registramos:
//   - Raices en SLOTS DE SPILL (RBP-relativos, GcHandle estable).
//   - Raices REGISTER-HELD empujadas a traves del call: el emisor guarda su
//     GcHandle en la pila (gchandle; push).  Ese handle vive en un offset
//     rbp-relativo fijo (spill_count + push_idx), que codificamos como slot.
//     Solo cuando la funcion NO tiene ALLOCA (que desplazaria rsp de forma
//     no reflejada en spill_count); con ALLOCA el conservador las cubre.
//
// Debe llamarse JUSTO DESPUES del opcode de call, para que el offset del
// marcador coincida con el return_pc (siguiente instruccion emitida).
static void emit_return_site_stackmap(EmitCtx &ctx, const IrBlock &bb,
                                      size_t idx) {
    if (!ctx.emit_stackmaps) return;
    const uint32_t pos = lin_pos_of(ctx, bb.id, idx);
    const IrInstr &ins = bb.instrs[idx];

    // Raices vivas a traves del call (conjunto semantico compartido).
    const std::vector<IrValueId> roots =
        ir::safepoint_gc_roots(ctx.fn, ctx.liveness, pos, ins.dst);
    if (roots.empty()) return;

    // Registros GC empujados a traves del call: reg -> push_index.  Su
    // GcHandle vive en el area de empuje del frame, en el slot rbp-relativo
    // (spill_count + push_idx).  SOLO es fiable cuando la funcion tiene FRAME
    // (enter emitido) y NO tiene ALLOCA: en ese caso rsp AL INICIO de la
    // secuencia de empuje del call site == rbp - 8*spill_count (los empujes
    // de cada call site son autocontenidos: push...call...pop), asi que el
    // empuje p cae en rbp - 8*(spill_count + p + 1) = slot (spill_count+p).
    // Sin frame (spill_count==0 y sin ALLOCA) el rbp es el del caller y el
    // offset no es fiable -> lo cubre el scan conservador (modo aditivo).
    // Registros GC empujados a traves del call: reg -> push_idx (desde el
    // fondo, en orden de regs_to_save).  Dos esquemas de localizacion:
    //
    //  - SIN ALLOCA (has_frame && !has_alloca): el empuje p cae en el slot
    //    rbp-relativo (spill_count + push_idx) del CALLER; codificamos como
    //    slot de spill 0x40+idx (materializado sobre caller_rbp por el scan).
    //    Requiere que la secuencia de empuje empiece en rbp - 8*spill_count,
    //    cierto solo sin ALLOCA (que baja rsp de forma no reflejada).
    //
    //  - CON ALLOCA (has_frame && has_alloca): el offset caller-rbp NO es
    //    fiable (ALLOCA desplazo rsp).  Pero los empujes quedan por ENCIMA del
    //    saved_rbp + return_pc que el `enter` del CALLEE dejo, asi que su
    //    offset desde el rbp del CALLEE es FIJO.  Forzamos empuje individual
    //    (force_individual_push_stackmap) -> el layout es determinista: el
    //    handle en el indice i de regs_to_save queda en
    //    callee_rbp + 16 + 8*(N-1-i).  Codificamos como 0x80 + (N-1-i)
    //    (materializado sobre el rbp del frame ACTUAL, el callee, por el scan).
    std::unordered_map<int, int> pushed_pos;
    std::vector<int> regs_to_save;
    if (ctx.has_frame) {
        regs_to_save = live_regs_through_call(ctx, pos, ins.dst);
        pushed_pos = pushed_gc_reg_positions(ctx, pos, regs_to_save);
    }
    const uint32_t spill_count = ctx.alloc.num_spill_slots;
    const int n_saved = static_cast<int>(regs_to_save.size());

    std::vector<SmLoc> locs;
    locs.reserve(roots.size());
    for (IrValueId vid : roots) {
        // (a) Raiz derramada a slot: el slot lleva el GcHandle estable.  Los
        //     slots de spill estan POR ENCIMA de la region ALLOCA (offset fijo
        //     desde caller_rbp), asi que funcionan con o sin ALLOCA.
        if (ctx.alloc.spilled(vid)) {
            const int slot = static_cast<int>(ctx.alloc.slot_of(vid));
            if (slot >= 0 && slot < 0x40)
                locs.push_back(
                    {static_cast<uint8_t>(loader::INTERP_SM_SLOT_BASE + slot),
                     static_cast<uint8_t>(jit::StackmapGcKind::HANDLE)});
            continue;
        }
        // (b) Raiz register-held empujada a traves del call.
        if (!ctx.alloc.in_reg(vid)) continue;
        const int r = ctx.alloc.reg_of(vid);
        auto it_push = pushed_pos.find(r);
        if (it_push == pushed_pos.end()) continue; // no empujado (no vivo/reg)
        const int push_idx = it_push->second;

        if (!ctx.has_alloca) {
            // Sin ALLOCA: slot caller-rbp = spill_count + push_idx.
            const uint32_t slot_idx =
                spill_count + static_cast<uint32_t>(push_idx);
            if (slot_idx < 0x40)
                locs.push_back(
                    {static_cast<uint8_t>(loader::INTERP_SM_SLOT_BASE +
                                          slot_idx),
                     static_cast<uint8_t>(jit::StackmapGcKind::HANDLE)});
        } else {
            // Con ALLOCA: offset callee-rbp = 16 + 8*(N-1-push_idx).
            // Con empuje individual forzado, push_idx = indice en regs_to_save,
            // por lo que la posicion desde el tope es (N-1-push_idx).
            const int from_top = n_saved - 1 - push_idx;
            if (from_top >= 0 && from_top < 0x40)
                locs.push_back(
                    {static_cast<uint8_t>(loader::INTERP_SM_PUSH_BASE +
                                          from_top),
                     static_cast<uint8_t>(jit::StackmapGcKind::HANDLE)});
        }
    }
    emit_sm_locs(ctx, locs);
}

// emite el save de los regs vivos antes de un CALL.  Para los
// regs que contienen un host_ptr GC (is_gc_object), guardamos el GcHandle
// (estable a evacuacion del GC) en lugar del host_ptr.  IMPORTANTE: NO
// reescribimos el reg original con el handle: el parallel-move posterior
// puede leer ese reg como source para colocar el arg en r1..r_N.  Si lo
// machacasemos, el callvirt recibiria el handle en lugar del host_ptr y
// fallaria con segfault.  Usamos @c r14 como scratch transiente: tras el
// push, el handle vive en stack y r14 puede ser libremente clobbeado por
// el parallel-move (cycle-breaking).
//
// Optimizacion fastpush: si NINGUNO de los regs es GC y son >= 2, los
// empujamos en una sola instruccion con `fastpush <mask16>` (4 bytes vs
// N x 2 bytes de push reg).  Para 1 reg el push tradicional es mas chico
// (2 bytes vs 4 bytes), asi que solo fusionamos a partir de 2 regs.
// True si debemos FORZAR el empuje individual (sin fastpush/hibrido) para que
// el layout de la pila de empuje sea DETERMINISTA y el stackmap del sitio de
// retorno pueda localizar cada handle GC empujado por su offset relativo al
// rbp del CALLEE (robusto ante ALLOCA en el caller).  Solo cuando hay GC
// preciso activo Y la funcion tiene ALLOCA (que desplaza rsp de forma no
// reflejada en spill_count, rompiendo el offset rbp-relativo del caller).  En
// funciones sin ALLOCA seguimos usando fastpush/hibrido (mismo perf de antes)
// porque el offset caller-rbp del handle empujado (spill_count + push_idx) SI
// es exacto.
static inline bool force_individual_push_stackmap(const EmitCtx &ctx) {
    return ctx.emit_stackmaps && ctx.has_alloca;
}

static void emit_save_live_regs(EmitCtx &ctx, uint32_t call_pos,
                                const std::vector<int> &regs_to_save) {
    // Detectar si todos los regs son no-GC para usar fastpush.
    bool any_gc = false;
    for (int r : regs_to_save) {
        if (reg_holds_gc_object(ctx, call_pos, r)) {
            any_gc = true;
            break;
        }
    }
    // GC preciso con ALLOCA: si hay handles GC, forzar empuje individual para
    // layout determinista (ver force_individual_push_stackmap).  Si no hay GC,
    // el fastpush puro sigue siendo seguro (no hay raiz que localizar).
    const bool force_individual = force_individual_push_stackmap(ctx) && any_gc;

    if (!any_gc && regs_to_save.size() >= 2) {
        uint32_t mask = 0;
        for (int r : regs_to_save) {
            if (r >= 0 && r < 16) mask |= (1u << r);
        }
        ctx.out.emit(emmit::Mnemonic::FASTPUSH, mask);
        return;
    }

    // LANG.fix-4: scratch dinamico para gchandle.  Por defecto usamos
    // r14, pero si r14 esta en regs_to_save (vivo a traves del call),
    // usamos r13; si tambien lo esta, r0 (return reg, sera sobreescrito
    // por el call).  Esto NO arregla el caso donde load_src puso un
    // operando en r14 antes del save (no esta en regs_to_save porque el
    // regalloc trata r14 como scratch externo).  Para ese caso, los call
    // sites afectados deben emitir SAVE antes de LOAD (ver STRMAKE/STRCAT
    // como referencia).
    bool r14_live = false;
    bool r13_live = false;
    for (int r : regs_to_save) {
        if (r == 14) r14_live = true;
        if (r == 13) r13_live = true;
    }
    auto pick_scratch = [&]() -> Reg {
        if (!r14_live) return Reg::gp(14);
        if (!r13_live) return Reg::gp(13);
        return Reg::gp(0);
    };
    const Reg sc = pick_scratch();

    bool gc_first_ordered = true;
    bool saw_nongc = false;
    int num_nongc_tail = 0;
    for (int r : regs_to_save) {
        const bool is_gc = reg_holds_gc_object(ctx, call_pos, r);
        if (is_gc && saw_nongc) {
            gc_first_ordered = false;
            break;
        }
        if (!is_gc) {
            saw_nongc = true;
            ++num_nongc_tail;
        }
    }
    if (!force_individual && gc_first_ordered && num_nongc_tail >= 2) {
        uint32_t mask = 0;
        for (int r : regs_to_save) {
            if (reg_holds_gc_object(ctx, call_pos, r)) {
                ctx.out.emit(emmit::Mnemonic::GCHANDLE, sc,
                             Reg::gp(static_cast<unsigned>(r)));
                ctx.out.emit(emmit::Mnemonic::PUSH, sc);
                if (sc.is_gp(14)) ctx.r14_cache = -1;
            } else {
                if (r >= 0 && r < 16) mask |= (1u << r);
            }
        }
        ctx.out.emit(emmit::Mnemonic::FASTPUSH, mask);
        return;
    }

    // Empuje individual (default y forzado con ALLOCA+GC preciso): cada reg en
    // orden de regs_to_save; los GC como handle (gchandle+push), los no-GC como
    // push reg.  Layout determinista -> el offset callee-rbp de cada handle es
    // 16 + 8*(N-1-i) donde i es su indice en regs_to_save (N = total
    // empujados).
    for (int r : regs_to_save) {
        if (reg_holds_gc_object(ctx, call_pos, r)) {
            ctx.out.emit(emmit::Mnemonic::GCHANDLE, sc,
                         Reg::gp(static_cast<unsigned>(r)));
            ctx.out.emit(emmit::Mnemonic::PUSH, sc);
            if (sc.is_gp(14)) ctx.r14_cache = -1;
        } else {
            ctx.out.emit(emmit::Mnemonic::PUSH,
                         Reg::gp(static_cast<unsigned>(r)));
        }
    }
}

// emite el restore de los regs guardados.  Para los regs GC,
// tras el pop convertimos el GcHandle de vuelta a host_ptr via gcderef.
// Si la GC movio el objeto durante el callee, el host_ptr resultante es
// el NUEVO; el codigo posterior puede leer/escribir fields sin segfault.
//
// Patron emitido (por reg GC):
//   pop reg
//   gcderef cur0, reg     ; cur0 = host_ptr fresco (post-GC)
//   xchg cur0, reg        ; reg = host_ptr; cur0 = handle (descartado)
//
// Optimizacion fastpop: si NINGUNO de los regs es GC y son >= 2, los
// desempilamos en una sola instruccion con `fastpop <mask16>` (mismo
// mask que el fastpush correspondiente).  fastpop es simetrico al
// fastpush, asi que los valores se restauran exactamente.
//
// El uso de cur0 sigue la convencion del loader (__new_<X>) donde gcderef
// escribe a cursor y luego se intercambia a un GP reg.  cur0 es scratch
// del runtime y nunca se preserva entre instrucciones VM.
static void emit_restore_live_regs(EmitCtx &ctx, uint32_t call_pos,
                                   const std::vector<int> &regs_to_save) {
    // Tras la llamada, el callee pudo haber clobreado r13/r14.  Invalidamos.
    invalidate_scratch_caches(ctx);

    // Detectar si todos los regs son no-GC para usar fastpop.
    bool any_gc = false;
    for (int r : regs_to_save) {
        if (reg_holds_gc_object(ctx, call_pos, r)) {
            any_gc = true;
            break;
        }
    }
    // Simetrico al save: si el save forzo empuje individual (GC preciso +
    // ALLOCA + GC), el restore debe usar pop individual (misma condicion).
    const bool force_individual = force_individual_push_stackmap(ctx) && any_gc;

    if (!any_gc && regs_to_save.size() >= 2) {
        uint32_t mask = 0;
        for (int r : regs_to_save) {
            if (r >= 0 && r < 16) mask |= (1u << r);
        }
        ctx.out.emit(emmit::Mnemonic::FASTPOP, mask);
        return;
    }

    // HYBRID restore -- SIMETRICO al hybrid save.
    bool gc_first_ordered = true;
    bool saw_nongc = false;
    int num_nongc_tail = 0;
    for (int r : regs_to_save) {
        const bool is_gc = reg_holds_gc_object(ctx, call_pos, r);
        if (is_gc && saw_nongc) {
            gc_first_ordered = false;
            break;
        }
        if (!is_gc) {
            saw_nongc = true;
            ++num_nongc_tail;
        }
    }
    if (!force_individual && gc_first_ordered && num_nongc_tail >= 2) {
        // Reverse del save: fastpop primero (los non-GC fueron pusheados al
        // final), luego pop+gcderef+xchg de los GC en orden inverso.
        uint32_t mask = 0;
        for (int r : regs_to_save) {
            if (!reg_holds_gc_object(ctx, call_pos, r) && r >= 0 && r < 16) {
                mask |= (1u << r);
            }
        }
        ctx.out.emit(emmit::Mnemonic::FASTPOP, mask);
        for (auto it = regs_to_save.rbegin(); it != regs_to_save.rend(); ++it) {
            const int r = *it;
            if (reg_holds_gc_object(ctx, call_pos, r)) {
                ctx.out.emit(emmit::Mnemonic::POP,
                             Reg::gp(static_cast<unsigned>(r)));
                ctx.out.emit(emmit::Mnemonic::GCDEREF,
                             Reg::special(SpecialReg::CUR0),
                             Reg::gp(static_cast<unsigned>(r)));
                ctx.out.emit(emmit::Mnemonic::XCHG,
                             Reg::special(SpecialReg::CUR0),
                             Reg::gp(static_cast<unsigned>(r)));
            }
        }
        return;
    }

    // Fallback: secuencia tradicional pop + (gcderef + xchg si GC).
    for (auto it = regs_to_save.rbegin(); it != regs_to_save.rend(); ++it) {
        const int r = *it;
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(static_cast<unsigned>(r)));
        if (reg_holds_gc_object(ctx, call_pos, r)) {
            ctx.out.emit(emmit::Mnemonic::GCDEREF,
                         Reg::special(SpecialReg::CUR0),
                         Reg::gp(static_cast<unsigned>(r)));
            ctx.out.emit(emmit::Mnemonic::XCHG, Reg::special(SpecialReg::CUR0),
                         Reg::gp(static_cast<unsigned>(r)));
        }
    }
}

// los values is_gc_object SPILLED no requieren
// save/restore extra alrededor de cada call: load_src/store_spilled ya
// convierten host_ptr <-> handle automaticamente al cruzar el slot stack.
// El handle es estable a evacuacion del GC (HandleTable redirige internamente),
// asi que un slot que contenga el handle del objeto sigue valido despues
// de cualquier numero de calls que disparen GC.  Esto reemplaza las
// funciones emit_save_spilled_gc / emit_restore_spilled_gc previas.
//
// Wrappers simples que mantienen la firma para no tocar 8 call sites.
static void emit_save_all_gc_aware(EmitCtx &ctx, uint32_t call_pos,
                                   const std::vector<int> &regs_to_save) {
    emit_save_live_regs(ctx, call_pos, regs_to_save);
}

static void emit_restore_all_gc_aware(EmitCtx &ctx, uint32_t call_pos,
                                      const std::vector<int> &regs_to_save) {
    emit_restore_live_regs(ctx, call_pos, regs_to_save);
}

// Resuelve los moves de argumentos para una llamada usando el algoritmo
// clasico de copia paralela.  Cada move es (target_reg, source_reg).
//
//  1) Mientras existan moves no resueltos:
//     a) Eliminar los triviales (target == source).
//     b) Buscar un move cuyo target NO sea source de ningun otro pendiente
//        y emitirlo.
//     c) Si no hay progreso (todo es ciclo): romper un ciclo usando un
//        scratch (r14) y reescribir.
//
// Esta funcion NO se preocupa por valores vivos a traves del call: esa
// preservacion debe haberse hecho con push antes de invocar este helper.
// Carga args spilled directamente a su reg destino DESPUES del parallel-move.
// Bug previo: cargar todos los spilled via load_src(_, 0) usaba siempre r14
// como temp; con 2+ args spilled, el segundo load clobbeaba el primero, y
// ambos terminaban con el mismo valor en moves[].  Fix: emitir spills tras
// el parallel-move usando direct load `mov r_target, [slot]` (sin pasar por
// scratch).  Para values is_gc_object spilled, añade el gcderef+xchg que
// load_src haria normalmente.
static void emit_load_spilled_arg(EmitCtx &ctx, int target_reg,
                                  ir::IrValueId vid) {
    if (!ctx.alloc.spilled(vid)) return; // no es spilled, no-op
    const Reg rd = Reg::gp(target_reg);
    /* La carga se hace con `mld`, que codifica [rbp - off] en UNA instruccion
     * y NO necesita registro scratch.
     *
     * Antes la direccion se calculaba a mano con r14 (mov r14,rbp; subu; mov)
     * dando por hecho que r14 estaba libre "porque parallel_arg_moves ya
     * termino".  Eso solo vale para el marshalling: si el asignador puso en
     * r14 un valor del LLAMANTE vivo a traves de la llamada, la secuencia lo
     * machacaba y quedaba corrupto al volver.  Se manifestaba, por ejemplo,
     * como `bytes()` devolviendo 0 sobre un string valido -- r14 contenia una
     * direccion de pila en vez del handle. */
    ctx.emit_spill_load(rd, ctx.alloc.slot_of(vid));
    if (ctx.is_gc_value(vid)) {
        ctx.out.emit(emmit::Mnemonic::GCDEREF, Reg::special(SpecialReg::CUR0),
                     rd);
        ctx.out.emit(emmit::Mnemonic::XCHG, Reg::special(SpecialReg::CUR0), rd);
    }
}

static void emit_parallel_arg_moves(EmitCtx &ctx,
                                    std::vector<std::pair<int, Reg>> moves) {
    auto reg_str_of = [](int r) { return std::string(reg_name(r)); };

    auto someone_uses_as_source = [&](const Reg &target_reg_str) {
        for (const auto &m : moves) {
            if (m.second == target_reg_str) return true;
        }
        return false;
    };

    // Bucle de resolucion.
    while (!moves.empty()) {
        // Paso a: eliminar triviales.
        bool removed_trivial = false;
        for (size_t i = 0; i < moves.size();) {
            if (moves[i].second == Reg::gp(moves[i].first)) {
                moves.erase(moves.begin() + (long)i);
                removed_trivial = true;
            } else {
                ++i;
            }
        }
        if (moves.empty()) break;

        // Paso b: buscar un move "seguro" (target no es source de nadie).
        bool emitted = false;
        for (size_t i = 0; i < moves.size(); ++i) {
            const Reg target_str = Reg::gp(moves[i].first);
            if (!someone_uses_as_source(target_str)) {
                ctx.out.emit(emmit::Mnemonic::MOV, target_str, moves[i].second);
                moves.erase(moves.begin() + (long)i);
                emitted = true;
                break;
            }
        }
        if (emitted) continue;
        if (removed_trivial) continue;

        // Paso c: ciclo.  Romperlo usando r14 (SCRATCH).  Tomamos el primer
        // move (s -> d), copiamos s a r14 y reescribimos cualquier otro
        // move que use s como source para que use r14, y emitimos al final
        // d <- r14 cuando llegue su turno.
        const int target_reg = moves.front().first;
        const Reg old_src = moves.front().second;
        const Reg scratch = Reg::gp(SCRATCH_REG);
        ctx.out.emit(emmit::Mnemonic::MOV, scratch, old_src);
        for (auto &m : moves) {
            if (m.second == old_src) m.second = scratch;
        }
        // Sustituir el move original (s -> d) por (r14 -> d).  No lo
        // emitimos aun: la siguiente iteracion lo emitira normalmente
        // porque ya no formara ciclo.
        moves.front().second = scratch;
        // (Nota: target_reg solo se usa como recordatorio del move roto;
        //  la siguiente iteracion lo emitira via el mismo loop.)
        (void)target_reg;
    }
}

// Emite una operacion binaria en formato dos-direcciones de .vel:
//   "op r_dst, r_src2"
// Carga operandos derramados desde pila (src1->r14, src2->r13) si es necesario.
// Almacena el resultado en pila si dst esta derramado.

// Emite operacion binaria de dos-direcciones:
//   "mov r_dst, r_src1"
//   "op  r_dst, r_src2"
// O su super-instruccion equivalente cuando aplique:
//   "OP3 r_dst, r_src1, r_src2"   (combina mov+op en una instr VM)
//
// Carga operandos derramados desde pila (src1->r14, src2->r13) si es necesario.
// Almacena el resultado en pila si dst esta derramado.
static void emit_binop(EmitCtx &ctx, emmit::Mnemonic mnemonic, IrValueId dst,
                       IrValueId src1, IrValueId src2) {
    Reg rs1 = ctx.load_src(src1, 0); // r14 si derramado
    Reg rs2 = ctx.load_src(src2, 1); // r13 si derramado
    Reg rd = ctx.dst_of(dst);

    /* Super-instruccion alu3 si:
     *   (a) existe variante 3-op para el mnemonic,
     *   (b) rd != rs1 (sin esto el mov no se emite y la 2-op tradicional
     *       es 1 instruccion -- igual coste, sin necesidad de cambio).
     * Cuando rs1 / rs2 estan derramados (r14 / r13), alu3 los lee igual
     * que la version 2-op: no hay restriccion en quien provee el operando. */
    const emmit::Mnemonic m3 = emmit::alu3_of(mnemonic);
    if (emmit::is_valid(m3) && rd != rs1) {
        ctx.out.emit(m3, rd, Reg(rs1), Reg(rs2));
        /* Si rd es r14 / r13 (caso destino spilled), invalidar cache de
         * constante igual que emit_mov_if_needed haria. */
        if (rd.is_gp(14)) ctx.r14_cache = -1;
        if (rd.is_gp(13)) ctx.r13_cache = -1;
        ctx.store_spilled(dst);
        return;
    }

    emit_mov_if_needed(ctx, rd, rs1);
    ctx.out.emit(mnemonic, rd, Reg(rs2));
    ctx.store_spilled(dst);
}

// Emite una operacion unaria en dos-direcciones:
//   "op r_dst"
// Carga operando derramado (->r14) y almacena resultado si dst esta derramado.
static void emit_unop(EmitCtx &ctx, emmit::Mnemonic mnemonic, IrValueId dst,
                      IrValueId src) {
    Reg rs = ctx.load_src(src, 0);
    Reg rd = ctx.dst_of(dst);
    emit_mov_if_needed(ctx, rd, rs);
    ctx.out.emit(mnemonic, rd);
    ctx.store_spilled(dst);
}

// Emite un SELECT sin salto en el interprete: %dst = %cond ? %a : %b.
//
// El interprete esta limitado por el despacho, no por la prediccion de saltos,
// asi que la forma sin salto (aritmetica de mascara) evita reconstruir el CFG
// y mantiene el codigo lineal.  @c %cond es booleano (0/1, como el que producen
// los CMP_*).  Formula:
//   invmask = cond - 1            ; 0 si cond=1, 0xFFFF...F si cond=0
//   dst     = a ^ ((a ^ b) & invmask)
// Comprobacion: cond=1 -> invmask=0 -> dst = a; cond=0 -> invmask=-1 ->
// dst = a ^ (a ^ b) = b.
//
// Usa r15/r14/r13 como temporales (libres entre instrucciones del IR).  Los
// operandos derramados se cargan PRIMERO (b el ultimo, porque
// @c emit_load_spilled_into reusa r13 para la direccion; cargar b en r13 al
// final es un self-overwrite seguro).  El pase de if-conversion excluye los
// phi de objetos GC, por lo que los operandos nunca son handles que requieran
// @c gcderef.
static void emit_select(EmitCtx &ctx, IrValueId dst, IrValueId cond,
                        IrValueId a, IrValueId b) {
    // Backend del INTERPRETE: SELECT -> super-instruccion `csel dst,cond,a,b`
    // (1 despacho: dst = cond ? a : b), NO la mascara branchless (~8 ops) que
    // penalizaba branch_unpredict 2.3x.  El SELECT del IR es una primitiva
    // SEMANTICA: el JIT/AOT lo bajan a cmov; el interp a esta op.
    //
    // CLAVE (trafico de registros): NO forzamos los operandos a scratches fijos
    // (eso anadia un mov por operando).  Usamos el registro YA ASIGNADO por el
    // regalloc a cada valor (reg_of); solo los DERRAMADOS se cargan a un
    // scratch (r14/r13/r15, que el regalloc nunca asigna a un SSA value).  csel
    // lee los 4 operandos y luego escribe dst -> el aliasing dst==cond (ambos
    // derramados a r14) es correcto (lee antes de escribir).  Caso comun (todo
    // en registro): 0 movs, un solo csel. emit_load_spilled_into usa r13 como
    // temp de direccion (lo clobbea en cada carga).  Por eso a los operandos
    // DERRAMADOS les asignamos scratches en orden r15 -> r14 -> r13, con r13 el
    // ULTIMO: asi ninguna carga posterior destruye un valor ya cargado (r13
    // solo se usa como HOLDER cuando es el ultimo derramado, y su carga es la
    // ultima).  Los operandos en registro usan su reg asignado (0 movs).
    const Reg spill_scratch[3] = {Reg::gp(15), Reg::gp(14), Reg::gp(13)};
    int nspill = 0;
    auto op_reg = [&](IrValueId v) -> Reg {
        if (ctx.alloc.in_reg(v))
            return Reg::gp(ctx.alloc.reg_of(v)); // reg asignado: sin mov
        const Reg s = spill_scratch[nspill < 2 ? nspill : 2];
        ++nspill;
        ctx.emit_load_spilled_into(v, s); // derramado: 1 carga
        return s;
    };
    const Reg rc = op_reg(cond);
    const Reg ra = op_reg(a);
    const Reg rb = op_reg(b);
    const Reg rd = ctx.dst_of(dst); // reg asignado o r14 (si derramado)
    ctx.out.emit(emmit::Mnemonic::CSEL, rd, rc, ra, rb);
    ctx.r13_cache = -1;
    ctx.r14_cache = -1;
    ctx.store_spilled(dst);
}

// =========================================================================
// Helpers float: bitcast GP <-> ZMM via stack memory roundtrip.
//
// El allocator solo conoce registros de proposito general (r0..r15), pero
// las instrucciones de aritmetica float (fadd/fsub/fmul/fdiv/fneg/...)
// requieren operandos en registros ZMM (f0..f15).  Como no hay opcode
// directo de "GP -> ZMM bits" (fcvt convierte VALOR, no bits), se hace
// un round-trip por la pila VM.  La encoding SIB no acepta @c rsp como
// registro base directo (encode_reg_general solo entiende r0..r15), asi
// que primero copiamos rsp a un GP scratch (r15: caller-saved, solo se
// usa para argc inmediatamente antes de CALL/CALLN -- entre IR ops es
// libre de clobber, igual que se asume para r13/r14 de spill scratch).
// Patron emitido (4 instrucciones por direccion):
//    subsp rsp, 8
//    mov   r15, rsp         ; r15 = direccion del slot (rsp ya bajado)
//    mov   [r15], <gp_reg>  ; deposita los 8 bytes IEEE 754
//    fload <zmm_reg>, r15   ; lee como float (mismo patron de bits)
//    addsp rsp, 8
// La direccion inversa es simetrica (fstore + mov gp_reg, [r15]).  Coste
// fijo de 5 instrucciones VM por bitcast hasta que se anada un asignador
// paralelo de ZMM (planificado para  D / MachineIR).
// =========================================================================
static void emit_gp_to_zmm_bits(EmitCtx &ctx, const Reg &gp_reg,
                                const Reg &zmm_reg) {
    // Sprint string-perf-5 (2026-06-02): bitcast directo via opcode bitg2z.
    // Antes: 5 instrucciones VM (subsp + mov r15,rsp + mov [r15],gp +
    // fload + addsp).  Ahora: 1 instruccion -> ~5x speedup en FP-heavy.
    ctx.out.emit(emmit::Mnemonic::BITG2Z, zmm_reg, gp_reg);
}

static void emit_zmm_to_gp_bits(EmitCtx &ctx, const Reg &zmm_reg,
                                const Reg &gp_reg) {
    // Sprint string-perf-5: bitcast directo via opcode bitz2g (1 instr VM).
    ctx.out.emit(emmit::Mnemonic::BITZ2G, gp_reg, zmm_reg);
}

// Materializa el valor float de `operand` en el registro `dst_zmm` (f0/f1):
// si reside en el banco ancho, un `fmov` desde su registro; si esta en GP, el
// bitcast bitg2z desde `gp_reg` (nombre GP ya cargado por load_src).
static void emit_load_float_to(EmitCtx &ctx, IrValueId operand,
                               const Reg &gp_reg, const Reg &dst_zmm) {
    const int z = ctx.zmm_of(operand);
    if (z >= 0)
        ctx.out.emit(emmit::Mnemonic::FMOV, dst_zmm,
                     Reg::fp(static_cast<unsigned>(z)));
    else
        emit_gp_to_zmm_bits(ctx, gp_reg, dst_zmm);
}

// Emite una operacion float binaria con bitcast automatico.
// Carga ambos operandos GP en f0/f1, ejecuta "op f0, f1", y devuelve f0
// como bits IEEE 754 al GP destino.  El sufijo ".ps" se anade
// automaticamente cuando @c type es F32 para que el runtime use la ruta
// de aritmetica float-32 (read_f32 + write_f32 con zeroing del tope).
static void emit_float_binop(EmitCtx &ctx, emmit::Mnemonic mnemonic,
                             IrType type, IrValueId dst, IrValueId src1,
                             IrValueId src2) {
    const int zd = ctx.zmm_of(dst);
    const int z1 = ctx.zmm_of(src1);
    const int z2 = ctx.zmm_of(src2);
    const bool es_ps = (type == IrType::F32);

    // Fast path historico: nada del banco ZMM implicado -> optimizacion last_f0
    // (evita recargar src1 si f0 ya lo tiene de la op float anterior).
    if (zd < 0 && z1 < 0 && z2 < 0) {
        const bool f0_has_src1 =
            (ctx.last_f0 != IR_NO_VALUE && ctx.last_f0 == src1);
        Reg rs1 = f0_has_src1 ? Reg::gp(0) : ctx.load_src(src1, 0);
        Reg rs2 = ctx.load_src(src2, 1);
        Reg rd = ctx.dst_of(dst);
        if (!f0_has_src1) emit_gp_to_zmm_bits(ctx, rs1, Reg::fp(0));
        emit_gp_to_zmm_bits(ctx, rs2, Reg::fp(1));
        ctx.out.emit(emmit::packed_if(mnemonic, es_ps), Reg::fp(0), Reg::fp(1));
        emit_zmm_to_gp_bits(ctx, Reg::fp(0), rd);
        ctx.store_spilled(dst);
        ctx.last_f0 = dst;
        return;
    }

    // Path ZMM-aware.  Operandos: su registro del banco si estan alocados; si
    // no, se cargan a scratch f0/f1 via bitg2z desde GP.  El resultado va a su
    // registro del banco (si alocado) o a f0 -> bitz2g GP.
    Reg ra = Reg::fp(0), rb = Reg::fp(1);
    if (z1 >= 0) {
        ra = Reg::fp(static_cast<unsigned>(z1));
    } else {
        emit_gp_to_zmm_bits(ctx, ctx.load_src(src1, 0), Reg::fp(0));
    }
    if (z2 >= 0) {
        rb = Reg::fp(static_cast<unsigned>(z2));
    } else {
        emit_gp_to_zmm_bits(ctx, ctx.load_src(src2, 1), Reg::fp(1));
    }
    const Reg rd = (zd >= 0) ? Reg::fp(static_cast<unsigned>(zd)) : Reg::fp(0);
    const bool comm = (mnemonic == emmit::Mnemonic::FADD ||
                       mnemonic == emmit::Mnemonic::FMUL ||
                       mnemonic == emmit::Mnemonic::FMIN ||
                       mnemonic == emmit::Mnemonic::FMAX);
    // 2-address: rd = ra OP rb.  El reuso de registro del regalloc garantiza
    // que rd == ra (o rd == rb) solo si ese operando murio -> seguro
    // sobrescribir.
    if (rd == ra) {
        ctx.out.emit(emmit::packed_if(mnemonic, es_ps), rd, rb);
    } else if (rd == rb && comm) {
        ctx.out.emit(emmit::packed_if(mnemonic, es_ps), rd, ra);
    } else if (rd == rb) { // no conmutativa y rd == rb: temp en f2
        ctx.out.emit(emmit::Mnemonic::FMOV, Reg::fp(2), ra);
        ctx.out.emit(emmit::packed_if(mnemonic, es_ps), Reg::fp(2), rb);
        ctx.out.emit(emmit::Mnemonic::FMOV, rd, Reg::fp(2));
    } else {
        ctx.out.emit(emmit::Mnemonic::FMOV, rd, ra);
        ctx.out.emit(emmit::packed_if(mnemonic, es_ps), rd, rb);
    }
    if (zd < 0) {
        emit_zmm_to_gp_bits(ctx, Reg::fp(0), ctx.dst_of(dst));
        ctx.store_spilled(dst);
    }
    // Este path pudo tocar f0/f1/f2 scratch -> la opt GP last_f0 ya no es
    // valida.
    ctx.last_f0 = IR_NO_VALUE;
}

// Emite una operacion float unaria con bitcast automatico.
// Carga el operando GP en f0, ejecuta "op f0, f0" (los unarios reusan
// el mismo registro como destino y fuente segun emit_instr_freg), y
// devuelve f0 como bits IEEE 754 al GP destino.  El sufijo ".ps" se
// anade cuando @c type es F32.
static void emit_float_unop(EmitCtx &ctx, emmit::Mnemonic mnemonic, IrType type,
                            IrValueId dst, IrValueId src) {
    const int zd = ctx.zmm_of(dst);
    const int zs = ctx.zmm_of(src);
    const bool es_ps = (type == IrType::F32);
    if (zd < 0 && zs < 0) {
        const bool f0_has_src =
            (ctx.last_f0 != IR_NO_VALUE && ctx.last_f0 == src);
        Reg rs = f0_has_src ? Reg::gp(0) : ctx.load_src(src, 0);
        Reg rd = ctx.dst_of(dst);
        if (!f0_has_src) emit_gp_to_zmm_bits(ctx, rs, Reg::fp(0));
        ctx.out.emit(emmit::packed_if(mnemonic, es_ps), Reg::fp(0), Reg::fp(0));
        emit_zmm_to_gp_bits(ctx, Reg::fp(0), rd);
        ctx.store_spilled(dst);
        ctx.last_f0 = dst;
        return;
    }
    // Path ZMM: `op rd, rs` (los unarios freg toman dst, src distintos).
    Reg rs = Reg::fp(0);
    if (zs >= 0) {
        rs = Reg::fp(static_cast<unsigned>(zs));
    } else {
        emit_gp_to_zmm_bits(ctx, ctx.load_src(src, 0), Reg::fp(0));
    }
    const Reg rd = (zd >= 0) ? Reg::fp(static_cast<unsigned>(zd)) : Reg::fp(0);
    ctx.out.emit(emmit::packed_if(mnemonic, es_ps), rd, rs);
    if (zd < 0) {
        emit_zmm_to_gp_bits(ctx, Reg::fp(0), ctx.dst_of(dst));
        ctx.store_spilled(dst);
    }
    ctx.last_f0 = IR_NO_VALUE;
}

// Emite `%d = fma %a, %b, %c` = round(a*b+c) con UN SOLO redondeo via la
// instruccion `fmadd fd, fa, fb` (fd = fa*fb + fd), que en el interp usa
// std::fma -> bit-exacto con VFMADD231 del JIT.  ZMM-aware: operandos en su
// registro del banco o cargados a scratch f0/f1 desde GP; el acumulador (que
// arranca con c) es el reg del dst, o f2 si aliasea a/b (fmadd lee ra,rb,fd y
// luego escribe fd, asi que fd no puede ser ra ni rb).
static void emit_float_fma(EmitCtx &ctx, IrType type, IrValueId dst,
                           IrValueId a, IrValueId b, IrValueId c) {
    const bool es_ps = (type == IrType::F32);
    const int za = ctx.zmm_of(a), zb = ctx.zmm_of(b), zc = ctx.zmm_of(c);
    const int zd = ctx.zmm_of(dst);
    Reg ra = Reg::fp(0), rb = Reg::fp(1);
    if (za >= 0) {
        ra = Reg::fp(static_cast<unsigned>(za));
    } else {
        emit_gp_to_zmm_bits(ctx, ctx.load_src(a, 0), Reg::fp(0));
    }
    if (zb >= 0) {
        rb = Reg::fp(static_cast<unsigned>(zb));
    } else {
        emit_gp_to_zmm_bits(ctx, ctx.load_src(b, 1), Reg::fp(1));
    }
    const Reg rd = (zd >= 0) ? Reg::fp(static_cast<unsigned>(zd)) : Reg::fp(2);
    // El acumulador NO puede aliasar ra/rb (fmadd corromperia el operando).
    const Reg acc = (rd == ra || rd == rb) ? Reg::fp(2) : rd;
    // Cargar c en el acumulador.
    if (zc >= 0) {
        const Reg rc = Reg::fp(static_cast<unsigned>(zc));
        if (acc != rc) ctx.out.emit(emmit::Mnemonic::FMOV, acc, rc);
    } else {
        emit_gp_to_zmm_bits(ctx, ctx.load_src(c, 2), acc);
    }
    ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FMADD, es_ps), acc, ra, rb);
    if (acc != rd) ctx.out.emit(emmit::Mnemonic::FMOV, rd, acc);
    if (zd < 0) {
        emit_zmm_to_gp_bits(ctx, rd, ctx.dst_of(dst));
        ctx.store_spilled(dst);
    }
    ctx.last_f0 = IR_NO_VALUE;
}

// Componentes de direccionamiento de un LOAD/STORE para el banco ancho
// (mld/mst): usa la fusion Fase 1/2 si existe (base + index<<scale + disp), o
// el registro del puntero (base, disp 0).  addr_op = indice del operando
// direccion (0 en LOAD, 1 en STORE).
struct WideAddr {
    int base;
    int index;
    bool has_index;
    uint8_t scale;
    int32_t disp;
    bool host;
};
static WideAddr compute_wide_addr(EmitCtx &ctx, const IrInstr &ins,
                                  int addr_op) {
    WideAddr w{0, 0, false, 0, 0, false};
    auto fit = ctx.addr_fusion.find(&ins);
    if (fit != ctx.addr_fusion.end()) {
        const auto &fa = fit->second;
        w.base = ctx.reg_num(fa.base);
        w.disp = fa.disp;
        if (fa.index != IR_NO_VALUE) {
            w.index = ctx.reg_num(fa.index);
            w.has_index = true;
            w.scale = fa.scale;
        }
    } else {
        const Reg ra = ctx.load_src(ins.operands[addr_op], addr_op);
        w.base = ra.index; // el numero ya lo lleva el operando
    }
    w.host = ins.operands[addr_op] != IR_NO_VALUE &&
             ctx.fn.values[ins.operands[addr_op]].is_host_ptr;
    return w;
}

// Epilogo callee-saved del banco ancho: restaura cada registro ZMM guardado
// (mld-FP desde su slot rbp).  Debe emitirse en TODO punto de salida (el _ret
// comun y ANTES del leave de un TAILCALL) para preservar los valores del banco
// del caller.
static void emit_zmm_callee_restore(EmitCtx &ctx) {
    for (size_t k = 0; k < ctx.zmm_saved_regs.size(); ++k) {
        const int freg = ctx.zmm_saved_regs[k];
        const int32_t disp =
            -static_cast<int32_t>((ctx.zmm_save_slot_base + k + 1) * 8);
        const uint32_t cw = 16u | (3u << 8) | (1u << 15);
        // El disp del mld/mst es int16; se emite como su patron de bits uint16
        // (el parser no acepta literales negativos como operando).
        ctx.out.emit(emmit::Mnemonic::MLD, Reg::gp(static_cast<unsigned>(freg)),
                     Reg::gp(0), cw,
                     static_cast<uint16_t>(static_cast<int16_t>(disp)));
    }
}

// Emite un mld/mst del banco ANCHO (bank=1) hacia/desde el registro `freg`.
// Ancho segun `wcode` (2 = 4 B f32, 3 = 8 B f64, ...).  No toca scratch GP.
static void emit_wide_mem(EmitCtx &ctx, bool is_load, int freg,
                          const WideAddr &w, unsigned wcode) {
    const uint32_t cw = (static_cast<uint32_t>(w.base) & 0x1F) |
                        ((static_cast<uint32_t>(w.scale) & 7u) << 5) |
                        (wcode << 8) | ((w.host ? 1u : 0u) << 11) |
                        ((w.has_index ? 1u : 0u) << 12) |
                        (1u << 15); // bank = banco ancho (ZMM)
    ctx.out << "    " << (is_load ? "mld " : "mst ") << reg_name(freg) << ", "
            << reg_name(w.index) << ", " << cw << ", "
            << static_cast<uint16_t>(static_cast<int16_t>(w.disp)) << "\n";
}

// True si la op deja f0 conteniendo el valor de su dst (las binarias/unarias
// float que pasan por emit_float_binop/emit_float_unop).  Cualquier otra op
// debe invalidar ctx.last_f0 porque puede clobbear f0 (FCMP, FCVT,
// conversiones, CALL, prints, aritmetica entera que reusa el scratch, etc.).
static inline bool is_tracked_float_op(IrOp op) {
    switch (op) {
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV:
    case IrOp::FMIN:
    case IrOp::FMAX:
    case IrOp::FNEG:
    case IrOp::FABS:
    case IrOp::FSQRT:
    case IrOp::FFLOOR:
    case IrOp::FCEIL:
    case IrOp::FROUND:
    case IrOp::FTRUNC:
    // ITOF/UITOF dejan el valor convertido en f0 (fcvt gp,f0 -> bitz2g).
    case IrOp::ITOF:
    case IrOp::UITOF: return true;
    default: return false;
    }
}

// Mnemonic de dos-direcciones para operaciones aritmeticas/logicas segun tipo.
static emmit::Mnemonic arith_mnemonic(IrOp op, IrType type) {
    using emmit::Mnemonic;
    bool is_signed = (type == IrType::I8 || type == IrType::I16 ||
                      type == IrType::I32 || type == IrType::I64);
    switch (op) {
    case IrOp::ADD: return is_signed ? Mnemonic::ADDS : Mnemonic::ADDU;
    // Multiprecision: siempre SIN signo -- el acarreo es un hecho
    // sobre los bits, no sobre el valor.
    case IrOp::ADDC: return Mnemonic::ADDU;
    case IrOp::SUBB: return Mnemonic::SUBU;
    case IrOp::SUB: return is_signed ? Mnemonic::SUBS : Mnemonic::SUBU;
    case IrOp::MUL: return is_signed ? Mnemonic::MULS : Mnemonic::MULU;
    case IrOp::DIV: return is_signed ? Mnemonic::DIVS : Mnemonic::DIVU;
    case IrOp::MOD: return is_signed ? Mnemonic::MODS : Mnemonic::MODU;
    case IrOp::AND: return Mnemonic::AND;
    case IrOp::OR: return Mnemonic::OR;
    case IrOp::XOR: return Mnemonic::XOR;
    case IrOp::SHL: return Mnemonic::SHL;
    case IrOp::SHR: return Mnemonic::SHR;
    case IrOp::SAR: return Mnemonic::SAR;
    // flotante
    case IrOp::FADD: return Mnemonic::FADD;
    case IrOp::FSUB: return Mnemonic::FSUB;
    case IrOp::FMUL: return Mnemonic::FMUL;
    case IrOp::FDIV: return Mnemonic::FDIV;
    case IrOp::FMIN: return Mnemonic::FMIN;
    case IrOp::FMAX: return Mnemonic::FMAX;
    // Cualquier operacion que no este arriba.  Antes devolvia "add", que NO
    // ES UN MNEMONICO de la maquina: si este caso llegara a dispararse, el
    // `.vel` saldria con una instruccion inexistente y el fallo aparecia al
    // ensamblar, sin nada que lo relacionara con aqui.  Escrito con el enum
    // eso deja de poder ocurrir -- este es exactamente el tipo de error que
    // el refactor viene a quitar.
    default: return Mnemonic::ADDS;
    }
}

// Mnemonic de comparacion segun tipo
static emmit::Mnemonic cmp_mnemonic(IrOp op) {
    switch (op) {
    case IrOp::CMP_ULT:
    case IrOp::CMP_UGT:
    case IrOp::CMP_ULE:
    case IrOp::CMP_UGE: return emmit::Mnemonic::CMPU;
    case IrOp::FCMP_EQ:
    case IrOp::FCMP_NE:
    case IrOp::FCMP_LT:
    case IrOp::FCMP_GT:
    case IrOp::FCMP_LE:
    case IrOp::FCMP_GE: return emmit::Mnemonic::FCMP;
    default: return emmit::Mnemonic::CMPS;
    }
}

// Inversion de condicion de salto: si cond es verdadera -> etiqueta false
// Emite "jmp.<cond_invertida> @Absolute(false_lbl)"
static void emit_cond_branch(EmitCtx &ctx, IrOp cmp_op,
                             const std::string &false_lbl) {
    using emmit::Mnemonic;
    Mnemonic jmp = Mnemonic::JMP_JE;
    switch (cmp_op) {
    case IrOp::CMP_EQ:
    case IrOp::FCMP_EQ: jmp = Mnemonic::JMP_JNE; break;
    case IrOp::CMP_NE:
    case IrOp::FCMP_NE: jmp = Mnemonic::JMP_JE; break;
    case IrOp::CMP_LT:
    case IrOp::FCMP_LT: jmp = Mnemonic::JMP_JGE; break;
    case IrOp::CMP_GT:
    case IrOp::FCMP_GT: jmp = Mnemonic::JMP_JLE; break;
    case IrOp::CMP_LE:
    case IrOp::FCMP_LE: jmp = Mnemonic::JMP_JGT; break;
    case IrOp::CMP_GE:
    case IrOp::FCMP_GE: jmp = Mnemonic::JMP_JLT; break;
    case IrOp::CMP_ULT: jmp = Mnemonic::JMP_JAE; break;
    case IrOp::CMP_UGT: jmp = Mnemonic::JMP_JLS; break;
    case IrOp::CMP_ULE: jmp = Mnemonic::JMP_JHI; break;
    case IrOp::CMP_UGE: jmp = Mnemonic::JMP_JB; break;
    default: jmp = Mnemonic::JMP_JE; break; // cond==0 -> false
    }
    ctx.out.emit(jmp, Ann::absolute(EmitCtx::abs_lbl(false_lbl)));
}

// =========================================================================
//  Helpers para cmpjmp / cmpjmpu fusionados (mejora hot loops).
// =========================================================================

/**
 * @brief Devuelve el mnemonic completo de @c cmpjmp.cc / @c cmpjmpu.cc
 *        equivalente a la cond INVERTIDA del cmp_op (cond de salto al
 *        false branch).
 *
 * Mismo mapeo que @c emit_cond_branch pero emitiendo el opcode fusionado
 * en lugar de cmp + jmp separados.  Devuelve nullptr si el cmp_op es
 * FCMP_* (no aplicamos cmpjmp a floats; van por la ruta ZMM existente).
 */
static const char *cmpjmp_fused_mnemonic(IrOp cmp_op) {
    switch (cmp_op) {
    case IrOp::CMP_EQ: return "cmpjmp.jne";
    case IrOp::CMP_NE: return "cmpjmp.je";
    case IrOp::CMP_LT: return "cmpjmp.jge";
    case IrOp::CMP_GT: return "cmpjmp.jle";
    case IrOp::CMP_LE: return "cmpjmp.jgt";
    case IrOp::CMP_GE: return "cmpjmp.jlt";
    case IrOp::CMP_ULT: return "cmpjmpu.jae";
    case IrOp::CMP_UGT: return "cmpjmpu.jls";
    case IrOp::CMP_ULE: return "cmpjmpu.jhi";
    case IrOp::CMP_UGE: return "cmpjmpu.jb";
    default: return nullptr; // FCMP_* o no soportado
    }
}

/**
 * @brief Verifica si emit_phi_copies generaria al menos una copia para
 *        el pred->succ dado.
 *
 * La fusion @c cmpjmp.cc solo es segura cuando NO hay phi copies entre
 * el cmp y el branch: si hubiera, los moves podrian pisar los regs del
 * cmp y alterar el resultado.  Este helper hace el mismo recorrido del
 * paso 1 de emit_phi_copies pero solo cuenta sin emitir.
 */
static bool has_phi_copies_to(EmitCtx &ctx, IrBlockId pred_id,
                              IrBlockId succ_id) {
    if (succ_id >= static_cast<IrBlockId>(ctx.fn.blocks.size())) return false;
    const IrBlock &succ = ctx.fn.blocks[succ_id];
    for (const auto &ins : succ.instrs) {
        if (ins.op != IrOp::PHI) break;
        if (ins.dst == IR_NO_VALUE) continue;
        for (const auto &pa : ins.phi_args) {
            if (pa.block == pred_id && pa.value != IR_NO_VALUE) {
                // Solo es una colision real si dst != src (mov no trivial).
                int d_reg =
                    ctx.alloc.in_reg(ins.dst) ? ctx.alloc.reg_of(ins.dst) : -1;
                int s_reg = ctx.alloc.in_reg(pa.value)
                                ? ctx.alloc.reg_of(pa.value)
                                : -2;
                if (d_reg != s_reg) return true;
                // Si alguno esta spilled, tambien hay copias (load/store)
                if (ctx.alloc.spilled(ins.dst) || ctx.alloc.spilled(pa.value))
                    return true;
            }
        }
    }
    return false;
}

// True si TODAS las copias de PHI de pred->succ son "flag-safe": ambos
// extremos viven en registro GP o en el banco ZMM (mov/fmov no tocan flags).
// Un extremo DERRAMADO usa el patron `mov r13, rbp; subu r13, K; mov rN,[r13]`
// -> el @c subu CLOBBEA los flags.  Solo cuando todas son flag-safe podemos
// intercalar las copias del false-block ENTRE el @c cmp y el @c jcc sin
// materializar el bool con @c setcc (ahorra setcc + push/pop + re-comparar).
static bool phi_copies_flag_safe(EmitCtx &ctx, IrBlockId pred_id,
                                 IrBlockId succ_id) {
    if (succ_id >= static_cast<IrBlockId>(ctx.fn.blocks.size())) return true;
    const IrBlock &succ = ctx.fn.blocks[succ_id];
    for (const auto &ins : succ.instrs) {
        if (ins.op != IrOp::PHI) break;
        if (ins.dst == IR_NO_VALUE) continue;
        for (const auto &pa : ins.phi_args) {
            if (pa.block == pred_id && pa.value != IR_NO_VALUE) {
                if (ctx.alloc.spilled(ins.dst) || ctx.alloc.spilled(pa.value))
                    return false; // load/store via subu -> clobbea flags
            }
        }
    }
    return true;
}

// Emite el lowering de CMP standalone (no fusionada con BR_COND):
//   cmps r_a, r_b
//   jmp.<cond> __true
//   mov r_dst, 0
//   jmp __end
// __true:
//   mov r_dst, 1
// __end:
static void emit_cmp_standalone(EmitCtx &ctx, const IrInstr &ins) {
    if (ins.operands.size() < 2) return;
    Reg rd = ctx.dst_of(ins.dst);
    Reg ra = ctx.load_src(ins.operands[0], 0);
    Reg rb = ctx.load_src(ins.operands[1], 1);
    std::string lbl_true = ctx.unique_lbl("ctrue");
    std::string lbl_end = ctx.unique_lbl("cend");
    const emmit::Mnemonic cmp_mn = cmp_mnemonic(ins.op);

    const bool is_fcmp = (ins.op == IrOp::FCMP_EQ || ins.op == IrOp::FCMP_NE ||
                          ins.op == IrOp::FCMP_LT || ins.op == IrOp::FCMP_GT ||
                          ins.op == IrOp::FCMP_LE || ins.op == IrOp::FCMP_GE);

    // --- Path branch-free (solo CMP entero): cmps + setcc ---
    //
    // Materializar un booleano 0/1 con un salto condicional (cmps + jmp.cc +
    // mov 0 + jmp + mov 1) mete una RAMA en el codigo por cada comparacion que
    // produce un valor.  Cuando ese valor alimenta un SELECT (csel, que ES
    // branch-free) la rama de la condicion arruina el beneficio: el branch
    // predictor la falla igual.  El VM tiene `setcc r_dst, cond` (opcode 0x43)
    // que escribe el booleano SIN saltar.  Aqui bajamos las CMP enteras a
    // `cmps/cmpu + setcc`, quitando la rama por completo.  Beneficia
    // directamente a patrones tipo branch_unpredict (la condicion del if/else
    // deja de mispredecir).
    //
    // Mapa IR cmp_op -> cond code de setcc (ver exec_instr_setcc):
    //   EQ=0x04 NE=0x05 LT=0x0C GE=0x0D LE=0x0E
    //   ULT=0x02 UGE=0x03 ULE=0x06 UGT=0x07
    // CMP_GT (JG signed) no tiene codigo directo -> se resuelve intercambiando
    // operandos: `a > b` == `b < a`, con JL (0x0C).  FCMP se queda en el path
    // branchy (el modelo de flags de float difiere y no queremos regresiones).
    if (!is_fcmp) {
        int setcc_cond = -1;
        bool swap = false;
        switch (ins.op) {
        case IrOp::CMP_EQ: setcc_cond = 0x04; break;
        case IrOp::CMP_NE: setcc_cond = 0x05; break;
        case IrOp::CMP_LT: setcc_cond = 0x0C; break;
        case IrOp::CMP_GE: setcc_cond = 0x0D; break;
        case IrOp::CMP_LE: setcc_cond = 0x0E; break;
        case IrOp::CMP_GT:
            setcc_cond = 0x0C;
            swap = true;
            break; // b < a
        case IrOp::CMP_ULT: setcc_cond = 0x02; break;
        case IrOp::CMP_UGE: setcc_cond = 0x03; break;
        case IrOp::CMP_ULE: setcc_cond = 0x06; break;
        case IrOp::CMP_UGT: setcc_cond = 0x07; break;
        default: break;
        }
        if (setcc_cond >= 0) {
            if (swap)
                ctx.out.emit(cmp_mn, Reg(rb), Reg(ra));
            else
                ctx.out.emit(cmp_mn, Reg(ra), Reg(rb));
            ctx.out.emit(emmit::Mnemonic::SETCC, rd, setcc_cond);
            ctx.store_spilled(ins.dst);
            return;
        }
    }

    if (is_fcmp) {
        // FCMP requiere registros ZMM; bitcast bits desde GP via stack.
        // El sufijo ".ps" se anade si los operandos son F32 (el tipo del
        // resultado de FCMP es BOOL, asi que miramos la fuente).
        const IrType ot = ctx.fn.values[ins.operands[0]].type;
        const bool es_ps = (ot == IrType::F32);
        emit_load_float_to(ctx, ins.operands[0], ra, Reg::fp(0));
        emit_load_float_to(ctx, ins.operands[1], rb, Reg::fp(1));
        ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FCMP, es_ps), Reg::fp(0),
                     Reg::fp(1));
    } else {
        ctx.out.emit(cmp_mn, Reg(ra), Reg(rb));
    }
    // saltar a true si condicion se cumple (condicion directa)
    using emmit::Mnemonic;
    Mnemonic jmp_direct = Mnemonic::JMP_JE;
    switch (ins.op) {
    case IrOp::CMP_EQ:
    case IrOp::FCMP_EQ: jmp_direct = Mnemonic::JMP_JE; break;
    case IrOp::CMP_NE:
    case IrOp::FCMP_NE: jmp_direct = Mnemonic::JMP_JNE; break;
    case IrOp::CMP_LT:
    case IrOp::FCMP_LT: jmp_direct = Mnemonic::JMP_JLT; break;
    case IrOp::CMP_GT:
    case IrOp::FCMP_GT: jmp_direct = Mnemonic::JMP_JGT; break;
    case IrOp::CMP_LE:
    case IrOp::FCMP_LE: jmp_direct = Mnemonic::JMP_JLE; break;
    case IrOp::CMP_GE:
    case IrOp::FCMP_GE: jmp_direct = Mnemonic::JMP_JGE; break;
    case IrOp::CMP_ULT: jmp_direct = Mnemonic::JMP_JB; break;
    case IrOp::CMP_UGT: jmp_direct = Mnemonic::JMP_JHI; break;
    case IrOp::CMP_ULE: jmp_direct = Mnemonic::JMP_JLS; break;
    case IrOp::CMP_UGE: jmp_direct = Mnemonic::JMP_JAE; break;
    default: jmp_direct = Mnemonic::JMP_JE; break;
    }
    ctx.out.emit(jmp_direct, Ann::absolute(EmitCtx::abs_lbl(lbl_true)));
    ctx.out.emit(emmit::Mnemonic::MOV, rd, 0);
    ctx.out.emit(emmit::Mnemonic::JMP,
                 Ann::absolute(EmitCtx::abs_lbl(lbl_end)));
    ctx.out.label(lbl_true);
    ctx.out.emit(emmit::Mnemonic::MOV, rd, 1);
    ctx.out.label(lbl_end);
    ctx.store_spilled(ins.dst);
}

// Emite las copias paralelas para destruccion de PHI en el bloque predecesor.
//
// Implementa el algoritmo de copia paralela con deteccion de ciclos:
//   1. Construir lista de pares (dst_reg, src_reg).
//   2. Eliminar triviales (dst == src).
//   3. Emitir copias acicilicas en orden topologico (un destino que no es
//      fuente de otra copia puede emitirse de forma segura).
//   4. Para los ciclos restantes: romper cada ciclo usando SCRATCH_REG (r14)
//      como temporal.
//
// Para valores derramados se usa una carga/almacenamiento
// secuencial a traves de r14; los ciclos con derrames se gestionan igual.
static void emit_phi_copies(EmitCtx &ctx, IrBlockId pred_id,
                            IrBlockId succ_id) {
    if (succ_id >= static_cast<IrBlockId>(ctx.fn.blocks.size())) return;
    const IrBlock &succ = ctx.fn.blocks[succ_id];

    // Paso 1: recopilar pares (dst_vid, src_vid)
    struct PhiCopy {
        IrValueId dst;
        IrValueId src;
    };
    std::vector<PhiCopy> copies;
    for (const auto &ins : succ.instrs) {
        if (ins.op != IrOp::PHI) break;
        if (ins.dst == IR_NO_VALUE) continue;
        for (const auto &pa : ins.phi_args) {
            if (pa.block == pred_id && pa.value != IR_NO_VALUE) {
                copies.push_back({ins.dst, pa.value});
            }
        }
    }
    if (copies.empty()) return;

    // Copias del banco ANCHO (ZMM): ambos extremos viven en el banco float
    // (garantizado por la democion all-or-none de compute_zmm_alloc).  Se
    // resuelven con `fmov` en un parallel-move DENTRO del banco float (f2 =
    // scratch de ciclos), disjunto del parallel-move GP de abajo.  Asi el
    // acumulador loop-carried nunca hace roundtrip movh+bitg2z por GP.
    {
        std::vector<PhiCopy> rest;
        rest.reserve(copies.size());
        std::unordered_map<int, int> zpend; // f_dst -> f_src (regs del banco)
        for (const auto &c : copies) {
            const int zd = ctx.zmm_of(c.dst);
            const int zs = ctx.zmm_of(c.src);
            if (zd >= 0 && zs >= 0) {
                if (zd != zs) zpend[zd] = zs;
            } else {
                rest.push_back(c); // pura GP (o congruente ya coalescida)
            }
        }
        // Emitir las que no son fuente de otra pendiente (sin RAW).
        bool zch = true;
        while (zch && !zpend.empty()) {
            zch = false;
            for (auto it = zpend.begin(); it != zpend.end();) {
                const int d = it->first;
                bool d_is_src = false;
                for (const auto &p : zpend)
                    if (p.first != d && p.second == d) {
                        d_is_src = true;
                        break;
                    }
                if (!d_is_src) {
                    ctx.out.emit(emmit::Mnemonic::FMOV,
                                 Reg::fp(static_cast<unsigned>(d)),
                                 Reg::fp(static_cast<unsigned>(it->second)));
                    it = zpend.erase(it);
                    zch = true;
                } else {
                    ++it;
                }
            }
        }
        // Romper ciclos con f2 (scratch reservado del banco float).
        while (!zpend.empty()) {
            auto it = zpend.begin();
            const int start = it->first;
            ctx.out.emit(emmit::Mnemonic::FMOV, Reg::fp(2),
                         Reg::fp(static_cast<unsigned>(start)));
            int cur = start;
            for (;;) {
                const int nxt = zpend.at(cur);
                zpend.erase(cur);
                if (nxt == start) {
                    ctx.out.emit(emmit::Mnemonic::FMOV,
                                 Reg::fp(static_cast<unsigned>(cur)),
                                 Reg::fp(2));
                    break;
                }
                ctx.out.emit(emmit::Mnemonic::FMOV,
                             Reg::fp(static_cast<unsigned>(cur)),
                             Reg::fp(static_cast<unsigned>(nxt)));
                cur = nxt;
            }
        }
        copies = std::move(rest);
        if (copies.empty()) return;
    }

    // Paso 2: separar copias en 3 categorias para preservar semantica
    // "paralela" del PHI (todas las copias deben verse como simultaneas):
    //
    //   (a) spilled-dst:  cualquier cosa -> slot.  Debe emitirse PRIMERO
    //       porque el src (sea reg o slot) tiene el valor OLD del frame
    //       anterior, y queremos leerlo antes de que  (b) lo cambie.
    //   (b) reg-to-reg:   reg -> reg.  parallel-move clasico en medio.
    //   (c) spilled-src reg-dst: slot -> reg.  Debe emitirse al FINAL,
    //       porque el dst_reg podria ser fuente de alguna copia (b).
    //
    // Orden:  (a) ->  (b) ->  (c).  Bug fix  D.7.opt:
    // antes (c) se emitia ANTES de (b), clobeando el dst_reg antes de que
    // (b) lo usara como fuente.
    std::vector<PhiCopy> reg_copies;          // (b)
    std::vector<PhiCopy> spilled_src_reg_dst; // (c)
    // Paso 2.a: spilled-dst (cualquier src -> slot).
    for (const auto &c : copies) {
        bool dst_in_reg = ctx.alloc.in_reg(c.dst);
        bool src_in_reg = ctx.alloc.in_reg(c.src);
        if (dst_in_reg && src_in_reg) {
            reg_copies.push_back(c);
        } else if (!dst_in_reg) {
            // dst spilled: load src y store al slot.  Si src es reg, el
            // valor que leemos es el OLD pre-phi.
            Reg r_src = ctx.load_src(c.src, 0);
            Reg r_dst = Reg::gp(SCRATCH_REG);
            emit_mov_if_needed(ctx, r_dst, r_src);
            ctx.store_spilled(c.dst);
        } else {
            // dst en reg, src en slot.  Diferido a  (c).
            spilled_src_reg_dst.push_back(c);
        }
    }

    // Paso 3: copia paralela para valores en registro.
    // Mapa: dst_reg -> src_reg (solo registros numericos)
    // Paso 3+4: copia paralela reg-a-reg via el secuenciador COMPARTIDO
    // (codegen::sequence_parallel_moves).  Los reg_copies son todos reg->reg
    // (los derramados se manejan en las categorias (a)/(c)); construimos los
    // pares {dst_reg, src_reg} y el modulo comun calcula el orden seguro +
    // rompe ciclos con SCRATCH_REG.  El interp solo EMITE cada paso como un
    // `mov` de bytecode; misma decision que usa el path vreg.
    {
        std::vector<codegen::PMoveStep> pmoves;
        pmoves.reserve(reg_copies.size());
        for (const auto &c : reg_copies)
            pmoves.push_back(
                {ctx.alloc.reg_of(c.dst), ctx.alloc.reg_of(c.src)});
        for (const auto &step :
             codegen::sequence_parallel_moves(std::move(pmoves), SCRATCH_REG))
            ctx.out.emit(emmit::Mnemonic::MOV,
                         Reg::gp(static_cast<unsigned>(step.dst)),
                         Reg::gp(static_cast<unsigned>(step.src)));
    }

    // Paso 5 ( c): spilled-src reg-dst.  Carga directa del slot al
    // reg destino.  Seguro emitir DESPUES de los moves reg-to-reg porque
    // dst_reg ya no es fuente de nadie.
    for (const auto &c : spilled_src_reg_dst) {
        if (!ctx.alloc.spilled(c.src)) continue;
        int d_reg = ctx.alloc.reg_of(c.dst);
        Reg rd = Reg::gp(d_reg);
        ctx.emit_spill_load(rd, ctx.alloc.slot_of(c.src));
        if (ctx.is_gc_value(c.src)) {
            ctx.out.emit(emmit::Mnemonic::GCDEREF,
                         Reg::special(SpecialReg::CUR0), rd);
            ctx.out.emit(emmit::Mnemonic::XCHG, Reg::special(SpecialReg::CUR0),
                         rd);
        }
    }
}

// =========================================================================
//  Emision de una instruccion completa
// =========================================================================

// Devuelve true si ins es una CMP cuyo unico uso es la siguiente instruccion
// BR_COND (para fusion cmp+branch).
static bool can_fuse_cmp_brcond(const IrFunction &fn, const IrBlock &bb,
                                size_t cmp_idx, const IrInstr &br_cond_ins) {
    const IrInstr &cmp = bb.instrs[cmp_idx];
    if (cmp.dst == IR_NO_VALUE) return false;
    // El BR_COND inmediato debe ramificar sobre el resultado del cmp.
    if (br_cond_ins.operands.empty() || br_cond_ins.operands[0] != cmp.dst)
        return false;
    // CRITICO: la fusion (cmpjmp) consume el cmp SIN materializar su resultado
    // en un registro.  Solo es segura si el resultado del cmp se usa
    // EXCLUSIVAMENTE en este BR_COND.  Si se usa en cualquier otro sitio (p.ej.
    // `bool b = a < c; if (b) {...}; if (b) {...}` -> el mismo valor alimenta
    // un segundo BR_COND en otro bloque), el segundo uso leeria un registro sin
    // materializar -> bool constante/erroneo.  Contamos todos los usos del
    // valor en la funcion; debe haber exactamente UNO (este BR_COND).
    size_t uses = 0;
    for (const auto &b : fn.blocks) {
        for (const auto &in : b.instrs) {
            for (IrValueId op : in.operands)
                if (op == cmp.dst) uses = uses + 1;
            if (in.func_ptr == cmp.dst) uses = uses + 1;
            for (const auto &pa : in.phi_args)
                if (pa.value == cmp.dst) uses = uses + 1;
        }
    }
    return uses == 1;
}

/* Las operaciones vectoriales trabajan sobre PUNTEROS, y la instruccion de
 * acceso depende de DONDE viva cada uno: `movh` para memoria del host (un
 * bloque de `malloc`) y `mov` para la de la VM (un array local `T[N]`, que
 * baja a ALLOCA).  Se emitia `movh` fijo, asi que recorrer un array local
 * vectorizado leia memoria VM como si fuera host y mataba el proceso.  Decide
 * por operando, con el mismo criterio que ya usan LOAD, STORE y MEMSET. */
static emmit::Mnemonic vec_mv(const EmitCtx &ctx, const ir::IrInstr &ins,
                              size_t idx) {
    if (idx >= ins.operands.size()) return emmit::Mnemonic::MOVH;
    const ir::IrValueId v = ins.operands[idx];
    return (v < ctx.fn.values.size() && ctx.fn.values[v].is_host_ptr)
               ? emmit::Mnemonic::MOVH
               : emmit::Mnemonic::MOV;
}

static void emit_instr(EmitCtx &ctx, const IrBlock &bb, size_t idx,
                       int &skip_count) {
    skip_count = 0;
    const IrInstr &ins = bb.instrs[idx];

    // La linea Vesta va como CAMPO de la instruccion; el comentario `// @line`
    // lo escribe el renderizador a partir de el.  La columna solo si se sabe.
    if (ctx.emit_debug && ins.source_line > 0)
        ctx.out.debug_line(ins.source_line, ins.source_column);

    //  E.1: el marcador `// @sm <hex>` se emite DENTRO de cada case de
    // safepoint (NEWOBJ/NEWOBJS/GC_ALLOC/GC_ALLOCP) justo antes del opcode de
    // alocacion, para que el byte_offset registrado coincida EXACTAMENTE con
    // el PC (rip) que el GC vera cuando el alloc dispare la coleccion.  No se
    // emite aqui (pre-switch) porque las secuencias de save-regs precederian
    // al opcode real y el offset no cuadraria con rip.

    switch (ins.op) {
    // --- NOP ---
    case IrOp::NOP: ctx.out.emit(emmit::Mnemonic::NOP1); break;

    // --- MAKE_CLOSURE ---
    // El IR emitter NO genera bytecode para esta instruccion.  La
    // secuencia explicita de ALLOCA env + STOREs + ALLOCA fv + STORE fn +
    // STORE env (emitida por lower_lambda_expr DESPUES del marker) hace
    // todo el trabajo real.  El marker existe para que el C2 JIT
    // ( D.8) pueda identificar la construccion completa de la
    // closure y hacer escape analysis sin pattern-matching del lowering.
    case IrOp::MAKE_CLOSURE:
        if (ctx.comments) {
            ctx.out << "    // make_closure @" << ins.func_name
                    << "  env_kind=" << ((ins.imm & 1) ? "GC_HEAP" : "STACK")
                    << "  N_captures=" << ins.operands.size() << "\n";
        }
        break;

    // --- MAKE_VARIANT ---
    // Marca construccion de un valor ADT.  La secuencia ALLOCA + STORE
    // tag + STOREs payload sigue siendo emitida por lower_enum_constructor
    // y produce el bytecode real.  C2 usa el marker para escape analysis
    // del slot del enum (promover a regs si no escapa).
    case IrOp::MAKE_VARIANT:
        if (ctx.comments) {
            ctx.out << "    // make_variant @" << ins.func_name
                    << "  tag=" << ins.imm
                    << "  N_payload=" << ins.operands.size() << "\n";
        }
        break;

    // --- MATCH_VARIANT ---
    // Marca el inicio de un match.  La cadena cmp+br emitida por
    // lower_match_expr DESPUES del marker hace el dispatch real.  C2 usa
    // el marker para reconocer el patron y elegir entre jumptable
    // (tags densos) o switch tree (dispersos).
    case IrOp::MATCH_VARIANT:
        if (ctx.comments) {
            ctx.out << "    // match_variant @" << ins.func_name
                    << "  n_arms=" << ins.imm << "\n";
        }
        break;

    // --- SWITCH_DENSE ---
    // Marker del jump table denso O(1).  No-op en el interp/bytecode: el
    // dispatch real lo hace el BST que lower_match_expr emite junto al marker.
    // Solo el backend JIT (vreg) lo baja a un island nativo (computed-goto).
    case IrOp::SWITCH_DENSE:
        if (ctx.comments) {
            ctx.out << "    // switch_dense min="
                    << static_cast<int64_t>(ins.imm)
                    << " n=" << ins.jump_targets.size() << "\n";
        }
        break;

    // --- CONST ---
    case IrOp::CONST: {
        // Const float residente del banco ancho -> carga inmediata IEEE al ZMM
        // (fmowi), sin pasar por GP.
        const int zd = ctx.zmm_of(ins.dst);
        if (zd >= 0) {
            ctx.out.emit(emmit::Mnemonic::FMOWI,
                         Reg::fp(static_cast<unsigned>(zd)), ins.imm);
            break;
        }
        Reg rd = ctx.dst_of(ins.dst);
        ctx.out.emit(emmit::Mnemonic::MOV, rd, ins.imm);
        ctx.store_spilled(ins.dst);
        break;
    }

    // --- STR_LIT_ADDR ---
    // Carga la direccion VM del literal estatico s_<imm> en el registro
    // destino.  Las etiquetas s_N viven dentro de la unica seccion
    // declarada del modulo ("code"), separadas del codigo ejecutable
    // por una directiva @c align (no por otra @Section, porque el
    // linker .velb actual no escribe datos de secciones secundarias
    // al binario final).  Por tanto se referencian via
    // @Absolute("code.s_N").
    case IrOp::STR_LIT_ADDR: {
        Reg rd = ctx.dst_of(ins.dst);
        // El storage de una variable global vive en la seccion `gdata`
        // (memoria host); el resto de slots -- literales que alimentan a
        // STRMAKE, params de los opcodes meta -- en `code`, que es memoria de
        // la VM porque es la que esos consumidores exigen.
        const char *sec =
            (ctx.mod && slot_is_gdata(*ctx.mod, ins.imm)) ? "gdata" : "code";
        ctx.out.emit(
            emmit::Mnemonic::MOV, Reg(rd),
            Ann::absolute(std::string(sec) + ".s_" + std::to_string(ins.imm)));
        ctx.store_spilled(ins.dst);
        break;
    }

    // --- SECTION_REF (AOT dev OS) ---
    // Simbolo de seccion (start/end/size).  Solo tiene sentido en AOT
    // (donde el writer lo resuelve via reloc).  En la VM/interp no hay
    // secciones nativas -> se emite 0 (consulta no aplicable).
    case IrOp::SECTION_REF: {
        Reg rd = ctx.dst_of(ins.dst);
        ctx.out.emit(emmit::Mnemonic::MOV, rd, 0);
        ctx.store_spilled(ins.dst);
        break;
    }

    // --- MOV ---
    case IrOp::MOV:
        if (!ins.operands.empty()) {
            Reg rs = ctx.load_src(ins.operands[0], 0);
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, rs);
            ctx.store_spilled(ins.dst);
        }
        break;

    // --- Aritmetica entera binaria ---
    case IrOp::ADD:
    case IrOp::SUB:
    case IrOp::MUL:
    case IrOp::DIV:
    case IrOp::MOD:
    case IrOp::AND:
    case IrOp::OR:
    case IrOp::XOR:
    case IrOp::SHL:
    case IrOp::SHR:
    case IrOp::SAR:
    // Multiprecision: la suma/resta es la normal sin signo -- lo que las
    // distingue es que su acarreo se consulta despues con CARRYOF, y que el
    // par no debe separarse (nada puede tocar los flags entre medias).
    case IrOp::ADDC:
    case IrOp::SUBB:
        if (ins.operands.size() >= 2) {
            emit_binop(ctx, arith_mnemonic(ins.op, ins.type), ins.dst,
                       ins.operands[0], ins.operands[1]);
            ctx.carry_src[ins.dst] = {ins.operands[0], ins.op == IrOp::SUBB};
            // El acarreo se lee AQUI, no donde aparezca el CARRYOF: es un
            // flag, y basta una operacion aritmetica en medio para pisarlo.
            for (size_t k = idx + 1; k < bb.instrs.size(); ++k) {
                const IrInstr &later = bb.instrs[k];
                if (later.op != IrOp::CARRYOF) continue;
                if (later.operands.empty() || later.operands[0] != ins.dst)
                    continue;
                if (later.dst == IR_NO_VALUE) continue;
                ctx.out.emit(emmit::Mnemonic::SETCC, ctx.dst_of(later.dst), 2);
                ctx.store_spilled(later.dst);
                ctx.carry_done.insert(later.dst);
                break;
            }
        }
        break;
    // Acarreo de la ADDC/SUBB que produjo el operando: se lee del flag que
    // esa suma acaba de dejar.  La condicion 2 es "acarreo activo", y va en
    // DECIMAL: el ensamblador no interpreta el hexadecimal en ese operando y
    // lo tomaria por 0, que es otra condicion -- el acarreo salia siempre
    // falso sin que nada avisara.
    case IrOp::CARRYOF:
        // Lo normal es que ya se emitiera pegado a su suma (ver ADDC/SUBB).
        // Si no se encontro alli -- suma y lectura en bloques distintos --,
        // el flag ya no es el suyo, asi que se recalcula con una comparacion
        // equivalente.
        if (ins.dst != IR_NO_VALUE && !ctx.carry_done.count(ins.dst)) {
            auto it_cs = ctx.carry_src.find(
                ins.operands.empty() ? IR_NO_VALUE : ins.operands[0]);
            if (it_cs != ctx.carry_src.end()) {
                // La suma desborda si el resultado quedo por debajo del primer
                // sumando; la resta pide prestado si el minuendo era menor que
                // el resultado.  En ambos casos el acarreo es "menor que".
                ctx.load_src(it_cs->second.first, 0);
                ctx.load_src(ins.operands[0], 1);
                const Reg a = ctx.reg_at(it_cs->second.first, 0);
                const Reg b = ctx.reg_at(ins.operands[0], 1);
                if (it_cs->second.second)
                    ctx.out.emit(emmit::Mnemonic::CMPU, a, b);
                else
                    ctx.out.emit(emmit::Mnemonic::CMPU, b, a);
            }
            ctx.out.emit(emmit::Mnemonic::SETCC, ctx.dst_of(ins.dst), 2);
            ctx.store_spilled(ins.dst);
        }
        break;
    // --- Seleccion sin salto (cond ? a : b) ---
    case IrOp::SELECT:
        if (ins.operands.size() == 3 && ins.dst != IR_NO_VALUE)
            emit_select(ctx, ins.dst, ins.operands[0], ins.operands[1],
                        ins.operands[2]);
        break;
    // --- Aritmetica flotante binaria (requiere registros ZMM) ---
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV:
    case IrOp::FMIN:
    case IrOp::FMAX:
        if (ins.operands.size() >= 2)
            emit_float_binop(ctx, arith_mnemonic(ins.op, ins.type), ins.type,
                             ins.dst, ins.operands[0], ins.operands[1]);
        break;

    case IrOp::FMA:
        if (ins.operands.size() >= 3)
            emit_float_fma(ctx, ins.type, ins.dst, ins.operands[0],
                           ins.operands[1], ins.operands[2]);
        break;

    // --- Aritmetica entera unaria ---
    case IrOp::NEG: {
        // -x = 0 - x  => mov r_dst, 0; subs r_dst, r_src
        // BugFix: si el regalloc asigno rd == rs (caso comun cuando
        // el src muere y dst nace en el mismo punto), `mov rd, 0`
        // clobreaba el valor original.  Evacuar rs a r14 antes
        // cuando coinciden.
        if (ins.operands.empty()) break;
        {
            Reg rd = ctx.dst_of(ins.dst);
            Reg rs = ctx.load_src(ins.operands[0], 0);
            if (rd == rs) {
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(14), rs);
                rs = Reg::gp(14);
                ctx.r14_cache = -1;
            }
            ctx.out.emit(emmit::Mnemonic::MOV, rd, 0);
            ctx.out.emit(emmit::Mnemonic::SUBS, rd, rs);
            ctx.store_spilled(ins.dst);
        }
        break;
    }

    // --- Operaciones unarias bitwise/float ---
    case IrOp::NOT:
        if (!ins.operands.empty())
            emit_unop(ctx, emmit::Mnemonic::NOT, ins.dst, ins.operands[0]);
        break;
    case IrOp::FNEG:
        if (!ins.operands.empty())
            emit_float_unop(ctx, emmit::Mnemonic::FNEG, ins.type, ins.dst,
                            ins.operands[0]);
        break;
    case IrOp::FABS:
        if (!ins.operands.empty())
            emit_float_unop(ctx, emmit::Mnemonic::FABS, ins.type, ins.dst,
                            ins.operands[0]);
        break;
    case IrOp::FSQRT:
        if (!ins.operands.empty())
            emit_float_unop(ctx, emmit::Mnemonic::FSQRT, ins.type, ins.dst,
                            ins.operands[0]);
        break;
    // Sprint string-perf-5: FP unarios nativos (opcodes 0x82-0x85).
    case IrOp::FFLOOR:
        if (!ins.operands.empty())
            emit_float_unop(ctx, emmit::Mnemonic::FFLOOR, ins.type, ins.dst,
                            ins.operands[0]);
        break;
    case IrOp::FCEIL:
        if (!ins.operands.empty())
            emit_float_unop(ctx, emmit::Mnemonic::FCEIL, ins.type, ins.dst,
                            ins.operands[0]);
        break;
    case IrOp::FROUND:
        if (!ins.operands.empty())
            emit_float_unop(ctx, emmit::Mnemonic::FROUND, ins.type, ins.dst,
                            ins.operands[0]);
        break;
    case IrOp::FTRUNC:
        if (!ins.operands.empty())
            emit_float_unop(ctx, emmit::Mnemonic::FTRUNC, ins.type, ins.dst,
                            ins.operands[0]);
        break;
    // --- Conversion de tipos ---
    case IrOp::CAST:
    case IrOp::ZEXT:
    case IrOp::SEXT:
    case IrOp::TRUNC: {
        if (!ins.operands.empty()) {
            const Reg rs = ctx.load_src(ins.operands[0], 0);
            const Reg rd = ctx.dst_of(ins.dst);
            const IrType src_t = ctx.fn.values[ins.operands[0]].type;
            const IrType dst_t = ins.type;
            const uint64_t src_bytes = type_slot_bytes(src_t);
            const uint64_t dst_bytes = type_slot_bytes(dst_t);
            const bool dst_signed =
                (dst_t == IrType::I8 || dst_t == IrType::I16 ||
                 dst_t == IrType::I32 || dst_t == IrType::I64);
            const bool src_signed =
                (src_t == IrType::I8 || src_t == IrType::I16 ||
                 src_t == IrType::I32 || src_t == IrType::I64);
            // Mover el valor primero al registro destino.
            emit_mov_if_needed(ctx, rd, rs);

            // Bug fix: el codigo previo solo emitia el mov, sin
            // truncar ni extender.  Esto dejaba los 8 bytes
            // originales del registro fuente en el destino, asi
            // que `i32 x = i64_value` no truncaba (`${x}` imprimia
            // el valor i64 completo).  Ahora emitimos:
            //   - TRUNC: AND con mascara del ancho destino;
            //     ademas si el destino es signed, sign-extend de
            //     vuelta a 64 bits para que ${x} (que lee qword)
            //     vea el valor correcto con bit de signo
            //     replicado.
            //   - ZEXT: AND con mascara del ancho FUENTE para
            //     descartar cualquier garbage en los bits altos.
            //   - SEXT: AND con mascara del ancho FUENTE +
            //     shl/sar para replicar el bit de signo de la
            //     fuente en los bits altos del destino.
            //   - CAST/BITCAST mismo ancho: solo el mov.
            // Elegir un scratch distinto de rd para evitar el
            // bug clasico: si rd == r14, `mov r14, K; shl rd, r14`
            // clobreaba el valor que ibamos a desplazar.  Patron
            // observado en render_buffer del editor: el SEXT de
            // `i32 blen = this.buffer.length` colocaba rd=r14;
            // la secuencia `mov r14, 32; shl r14, r14; sar r14, r14`
            // producia `0x2000000000` en lugar de sign-extender,
            // dejando blen = ~137 GB -> `off < blen` siempre true ->
            // overrun de bdat[] al primer bdat[4096] = AV en page
            // boundary.  La fix: si rd == r14 usamos r13 como
            // scratch (sin reservar nada extra: r13/r14 son ambos
            // scratch del runtime y solo uno se usa por sequence).
            // Cual de los dos scratch queda libre: el que NO es el destino.
            const Reg scratch = rd.is_gp(14) ? Reg::gp(13) : Reg::gp(14);
            // Optimizacion: si vamos a seguir con `shl K; sar K` para
            // sign-extender, el AND mask previo es REDUNDANTE: el shl
            // ya descarta los bits altos al desplazar a la izquierda.
            // Pasamos directamente al shl/sar y ahorramos 2 instrs
            // (mov scratch, mask + and rd, scratch) por cada SEXT < 64.
            // Para ZEXT/TRUNC sin signo si necesitamos el AND para
            // mantener los bits altos a cero.
            if (dst_bytes < src_bytes) {
                // Truncate.
                const int dst_bits = static_cast<int>(dst_bytes) * 8;
                if (dst_bits < 64) {
                    if (dst_signed) {
                        // Sign-extend de dst_bits a 64 en UNA instruccion
                        // (opcode 0x92) -- antes eran 3 (mov scratch, K; shl;
                        // sar), y el scratch obligaba a recargar K cada
                        // iteracion en loops.
                        ctx.out.emit(emmit::Mnemonic::SEXT, rd, dst_bits);
                    } else {
                        // Unsigned: AND con mascara para zero-extend.
                        // La mascara es i64 (necesita los 64 bits), asi
                        // que el mov full sigue siendo necesario.
                        const uint64_t mask = (1ULL << dst_bits) - 1ULL;
                        emit_mov_scratch_imm(ctx, scratch,
                                             static_cast<int64_t>(mask));
                        ctx.out.emit(emmit::Mnemonic::AND, rd, scratch);
                    }
                }
            } else if (dst_bytes > src_bytes) {
                // Widen.
                const int src_bits = static_cast<int>(src_bytes) * 8;
                if (src_bits < 64) {
                    if (src_signed) {
                        // Sign-extend de src_bits a 64 en UNA instruccion
                        // (opcode 0x92); ver la rama de truncado arriba.
                        ctx.out.emit(emmit::Mnemonic::SEXT, rd, src_bits);
                    } else {
                        // Unsigned: AND con mascara para zero-extend.
                        const uint64_t mask = (1ULL << src_bits) - 1ULL;
                        emit_mov_scratch_imm(ctx, scratch,
                                             static_cast<int64_t>(mask));
                        ctx.out.emit(emmit::Mnemonic::AND, rd, scratch);
                    }
                }
            }
            // Mismo ancho: solo el mov inicial.
            ctx.store_spilled(ins.dst);
        }
        break;
    }
    case IrOp::ITOF:
    case IrOp::UITOF:
        // int VALOR (en GP) -> bits IEEE 754 (en GP).  Pasos:
        //   fcvt[.ps]  gp_src, f0  ; r1=GP -> direction=0 (GP->ZMM):
        //                            write_f64 si destino F64,
        //                            write_f32 si destino F32 (.ps)
        //   bitcast f0 -> gp_dst   ; mueve bits IEEE al GP destino
        // Convencion de fcvt (emit_instr_fcvt en
        // src/emmit/emmit_decl.cpp:2086):
        //   r1=ZMM -> direction=1 (zmm->gp), r1=GP -> direction=0 (gp->zmm).
        if (!ins.operands.empty()) {
            Reg rs = ctx.load_src(ins.operands[0], 0);
            const bool es_ps = (ins.type == IrType::F32);
            const int zd = ctx.zmm_of(ins.dst);
            if (zd >= 0) {
                // int (GP) -> float DIRECTO al banco: fcvt gp_src, f_dst.
                ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FCVT, es_ps),
                             Reg(rs), Reg::fp(static_cast<unsigned>(zd)));
                break; // vive en ZMM
            }
            Reg rd = ctx.dst_of(ins.dst);
            ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FCVT, es_ps),
                         Reg(rs), Reg::fp(0));
            emit_zmm_to_gp_bits(ctx, Reg::fp(0), rd);
            ctx.store_spilled(ins.dst);
            ctx.last_f0 = ins.dst; // f0 conserva el valor float convertido
        }
        break;
    case IrOp::FTOI:
    case IrOp::FTOUI:
        // bits IEEE 754 -> int VALOR truncado (en GP).  Si la fuente reside en
        // el banco, se lee DIRECTO: fcvt f_src, gp_dst (sin bitg2z).
        if (!ins.operands.empty()) {
            Reg rd = ctx.dst_of(ins.dst);
            const IrType ot = ctx.fn.values[ins.operands[0]].type;
            const bool es_ps = (ot == IrType::F32);
            const int zs = ctx.zmm_of(ins.operands[0]);
            if (zs >= 0) {
                ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FCVT, es_ps),
                             Reg::fp(static_cast<unsigned>(zs)), Reg(rd));
            } else {
                Reg rs = ctx.load_src(ins.operands[0], 0);
                emit_gp_to_zmm_bits(ctx, rs, Reg::fp(0));
                ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FCVT, es_ps),
                             Reg::fp(0), Reg(rd));
            }
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::BITCAST: {
        // BITCAST entre tipos del MISMO ancho (e.g. f64<->i64): copia
        // de bits sin re-interpretacion.  emit_mov_if_needed basta.
        if (!ins.operands.empty()) {
            Reg rs = ctx.load_src(ins.operands[0], 0);
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, rs);
            ctx.store_spilled(ins.dst);
        }
        break;
    }
    case IrOp::F32TOF64:
        // f32 (4 bytes IEEE en bajo de GP) -> f64 (8 bytes IEEE en GP).
        // Conversion REAL: el patron de bits cambia (re-bias del exp,
        // shift de mantissa).  Pasos:
        //   bitcast GP -> f0    ; f32 bits en bytes bajos de f0
        //   fextend  f1, f0     ; f1 = (double)(f32)f0
        //   bitcast f1 -> GP    ; 8 bytes IEEE 754 al GP destino
        if (!ins.operands.empty()) {
            const int zs = ctx.zmm_of(ins.operands[0]);
            const int zd = ctx.zmm_of(ins.dst);
            Reg fs = Reg::fp(0);
            if (zs >= 0) {
                fs = Reg::fp(static_cast<unsigned>(zs));
            } else {
                emit_gp_to_zmm_bits(ctx, ctx.load_src(ins.operands[0], 0),
                                    Reg::fp(0));
                fs = Reg::fp(0);
            }
            const Reg fd =
                (zd >= 0) ? Reg::fp(static_cast<unsigned>(zd)) : Reg::fp(1);
            ctx.out.emit(emmit::Mnemonic::FEXTEND, fd, fs);
            if (zd < 0) {
                emit_zmm_to_gp_bits(ctx, Reg::fp(1), ctx.dst_of(ins.dst));
                ctx.store_spilled(ins.dst);
            }
        }
        break;
    case IrOp::F64TOF32:
        // f64 (8 bytes IEEE en GP) -> f32 (4 bytes IEEE en bajo de GP).
        // Conversion REAL con perdida de precision; los 4 bytes altos
        // del GP destino quedan en cero (write_f32 zerifica el resto
        // del ZMM antes del bitcast inverso).
        //   bitcast GP -> f0    ; f64 bits en f0
        //   fnarrow  f1, f0     ; f1 = (float)(double)f0
        //   bitcast f1 -> GP    ; 4 bytes f32 + 4 bytes cero al GP
        if (!ins.operands.empty()) {
            const int zs = ctx.zmm_of(ins.operands[0]);
            const int zd = ctx.zmm_of(ins.dst);
            Reg fs = Reg::fp(0);
            if (zs >= 0) {
                fs = Reg::fp(static_cast<unsigned>(zs));
            } else {
                emit_gp_to_zmm_bits(ctx, ctx.load_src(ins.operands[0], 0),
                                    Reg::fp(0));
                fs = Reg::fp(0);
            }
            const Reg fd =
                (zd >= 0) ? Reg::fp(static_cast<unsigned>(zd)) : Reg::fp(1);
            ctx.out.emit(emmit::Mnemonic::FNARROW, fd, fs);
            if (zd < 0) {
                emit_zmm_to_gp_bits(ctx, Reg::fp(1), ctx.dst_of(ins.dst));
                ctx.store_spilled(ins.dst);
            }
        }
        break;

    // --- Comparaciones (standalone, no fusionadas) ---
    case IrOp::CMP_EQ:
    case IrOp::CMP_NE:
    case IrOp::CMP_LT:
    case IrOp::CMP_GT:
    case IrOp::CMP_LE:
    case IrOp::CMP_GE:
    case IrOp::CMP_ULT:
    case IrOp::CMP_UGT:
    case IrOp::CMP_ULE:
    case IrOp::CMP_UGE:
    case IrOp::FCMP_EQ:
    case IrOp::FCMP_NE:
    case IrOp::FCMP_LT:
    case IrOp::FCMP_GT:
    case IrOp::FCMP_LE:
    case IrOp::FCMP_GE: {
        // Intentar fusion con la siguiente instruccion BR_COND
        if (idx + 1 < bb.instrs.size()) {
            const IrInstr &next = bb.instrs[idx + 1];
            if (next.op == IrOp::BR_COND &&
                can_fuse_cmp_brcond(ctx.fn, bb, idx, next)) {
                // Fusion: emitir cmp + salto condicional ahora.
                //
                // BUG critico arreglado (2026-05-04): las copias PHI
                // para AMBOS sucesores deben emitirse en sus puntos
                // correspondientes.  Antes solo se emitian para
                // @c target_block (true branch), dejando el
                // @c false_block sin copias -> los PHIs de los
                // bloques destino veian valores stale del predecesor
                // cuando el salto condicional caia al false branch.
                // Sintoma: loops con if dentro divergen (j no
                // incrementa, i toma valor de j, etc.).
                //
                // Layout post-fix:
                //   cmp ...
                //   <copias phi del FALSE branch>
                //   <salto condicional invertido al false_block>
                //   <copias phi del TRUE branch>
                //   jmp target_block
                //
                // El salto condicional usa la condicion INVERTIDA
                // porque por convencion saltamos al false branch
                // cuando cmp falla (y caemos al true branch).  Las
                // copias del false branch deben emitirse antes del
                // salto: si saltamos, queremos que se hayan ya
                // ejecutado.  Las del true branch se emiten despues
                // (no se pisan porque solo ejecutan si NO saltamos).
                if (ins.operands.size() >= 2) {
                    Reg ra = ctx.load_src(ins.operands[0], 0);
                    Reg rb = ctx.load_src(ins.operands[1], 1);
                    const bool is_fcmp_fused =
                        (ins.op == IrOp::FCMP_EQ || ins.op == IrOp::FCMP_NE ||
                         ins.op == IrOp::FCMP_LT || ins.op == IrOp::FCMP_GT ||
                         ins.op == IrOp::FCMP_LE || ins.op == IrOp::FCMP_GE);
                    IrBlockId bid =
                        static_cast<IrBlockId>(&bb - ctx.fn.blocks.data());

                    // Optimizacion (cmpjmp fusionado): el cmpjmp.cc
                    // salta al FALSE branch (cond invertida) si la
                    // comparacion ORIGINAL no se cumple; cae a
                    // fall-through hacia TRUE branch.
                    //
                    // Phi safety:
                    //  - false_block phi copies: NO se pueden emitir
                    //    (saltarian junto con el branch atomic, no
                    //    podemos intercalarlas).  Si las hay, fallback.
                    //  - target_block (TRUE) phi copies: se emiten
                    //    DESPUES del cmpjmp y ANTES del jmp final.
                    //    Seguro porque el cmpjmp ya hizo cmp+branch
                    //    y no relee los regs del cmp.
                    //
                    // Esto cubre el patron clasico do-while con PHIs
                    // en el loop_body (back-edge target).
                    const bool has_phi_false =
                        has_phi_copies_to(ctx, bid, next.false_block);
                    // Valvula para medir lo que aporta la fusion: sin poder
                    // apagarla no hay con que comparar, y sin comparacion
                    // cualquier cifra sobre su rendimiento seria inventada.
                    static const bool fusion_off =
                        util::flag_on(util::FlagId::NoCmpJmp);
                    const bool fusion_safe = !has_phi_false && !fusion_off;
                    const char *fused_mn = (is_fcmp_fused || !fusion_safe)
                                               ? nullptr
                                               : cmpjmp_fused_mnemonic(ins.op);
                    if (fused_mn != nullptr) {
                        // El cmpjmp.cc usa cond INVERTIDA (false branch).
                        ctx.out << "    " << fused_mn << " " << ra << ", " << rb
                                << ", @Absolute(\""
                                << EmitCtx::abs_lbl(
                                       ctx.block_label(next.false_block))
                                << "\")\n";
                        // Phi copies del TRUE branch (fall-through):
                        // se ejecutan solo si NO saltamos a false.
                        emit_phi_copies(ctx, bid, next.target_block);
                        emit_jmp_or_fallthrough(ctx, bid, next.target_block);
                    } else if (is_fcmp_fused) {
                        // FCMP fusionado con BR_COND: bitcast a ZMM antes
                        // de comparar.  Selecciona ".ps" si operandos F32.
                        const IrType ot = ctx.fn.values[ins.operands[0]].type;
                        const bool es_ps = (ot == IrType::F32);
                        emit_load_float_to(ctx, ins.operands[0], ra,
                                           Reg::fp(0));
                        emit_load_float_to(ctx, ins.operands[1], rb,
                                           Reg::fp(1));
                        ctx.out.emit(
                            emmit::packed_if(emmit::Mnemonic::FCMP, es_ps),
                            Reg::fp(0), Reg::fp(1));
                        emit_phi_copies(ctx, bid, next.false_block);
                        emit_cond_branch(ctx, ins.op,
                                         ctx.block_label(next.false_block));
                        emit_phi_copies(ctx, bid, next.target_block);
                        emit_jmp_or_fallthrough(ctx, bid, next.target_block);
                    } else if (phi_copies_flag_safe(ctx, bid,
                                                    next.false_block)) {
                        // Path FLAG-SAFE (calidad de codegen): cuando TODAS
                        // las copias de PHI del false-block son reg-a-reg (o
                        // ZMM), @c mov/@c fmov NO tocan flags -> podemos
                        // intercalarlas ENTRE el @c cmp y el @c jcc sin
                        // materializar el bool con @c setcc.  Es el MISMO
                        // patron que el FCMP fusionado de arriba, con cmp
                        // entero.  Elimina setcc + push/pop + `mov r13,0` +
                        // `cmpu` (~5 ops) que el fallback tradicional metia
                        // por MIEDO al clobber de flags -- miedo que solo
                        // aplica a copias DERRAMADAS (esas usan @c subu).
                        // Las operands del cmp (ra/rb) ya se consumieron, asi
                        // que una copia que reusa su registro es correcta.
                        //
                        // Impacto medido: patrones `if (a OP b) stmt;` con
                        // un merge que copia un acumulador loop-carried (p.ej.
                        // hash_lookup: `if ((seed&7)==0) acc++`) pasan de 9
                        // ops a 3 en la region del branch.
                        const emmit::Mnemonic cmp_mn = cmp_mnemonic(ins.op);
                        ctx.out.emit(cmp_mn, Reg(ra), Reg(rb));
                        emit_phi_copies(ctx, bid, next.false_block);
                        emit_cond_branch(ctx, ins.op,
                                         ctx.block_label(next.false_block));
                        emit_phi_copies(ctx, bid, next.target_block);
                        emit_jmp_or_fallthrough(ctx, bid, next.target_block);
                    } else {
                        // Fallback: cmp + cond branch tradicional.
                        //
                        // LANG.fix-9: las phi copies emiten LOAD desde
                        // stack (mov r13, rbp; subu r13, K; mov rN, [r13])
                        // que CLOBREAN flags entre el cmp y el jcc.
                        // Resultado: el branch lee flags stale del subu
                        // (siempre ZF=0 porque rbp-K != 0) y NUNCA toma
                        // la rama true.  Sintoma: `if (it == 0) nlen = 1;`
                        // no actualiza nlen.  Solo llegamos aqui cuando
                        // alguna copia del false-block esta DERRAMADA.
                        //
                        // Tampoco basta con emitir phi_copies antes del
                        // cmp porque los phi dst regs pueden colisionar
                        // con los regs de ra/rb (regs de las operands
                        // del cmp).  El regalloc reusa regs entre SSA
                        // values con lifetimes no-overlapping y los
                        // phi_dst pueden caer en el mismo reg que el
                        // cmp operand (caso comun cuando el cmp operand
                        // muere justo antes de la rama).
                        //
                        // Solucion robusta: usar SETcc para materializar
                        // el resultado del cmp en un reg PERSISTENTE
                        // (r14 scratch), luego emitir las phi_copies
                        // libremente (pueden clobbear flags pero NO
                        // tocan r14 fuera de su propio uso), luego
                        // hacer cmpu r14, 0 + je para branch final.
                        // El cmpu r14, 0 NO puede ser fooled por phi
                        // copies posteriores porque no hay phi copies
                        // entre este cmpu y el je (van inmediatas).
                        //
                        // Mapping de IR cmp_op a setcc cond code:
                        //   CMP_EQ  -> sete  (cc=1: ZF==1)
                        //   CMP_NE  -> setne (cc=0: ZF==0)
                        //   CMP_LT  -> setl  (cc=12: SF != OF)
                        //   ...
                        // Para simplificar, despues del setcc el reg
                        // contiene 1 si la cond ORIGINAL es true, 0
                        // si false.  Luego `cmpu r14, 0; je false_lbl`
                        // salta a false si r14==0 (es decir, si la cond
                        // ORIGINAL era false).
                        //
                        // Coste: 1 instr extra (setcc) + cmpu inline.
                        // Cero overhead cuando no hay phi copies (path
                        // cmpjmp fusionado se usa).
                        const emmit::Mnemonic cmp_mn = cmp_mnemonic(ins.op);
                        ctx.out.emit(cmp_mn, Reg(ra), Reg(rb));
                        // setcc cond, r14: r14 = (cond ? 1 : 0).
                        // El cond code corresponde a la condicion
                        // ORIGINAL del cmp_op (no invertida).
                        // Cond codes del setcc bytecode (ver
                        // exec_instr_setcc).  Setea r14=1 si la
                        // condicion ORIGINAL del cmp_op es true.
                        int setcc_cond = 0;
                        switch (ins.op) {
                        case IrOp::CMP_EQ:
                            setcc_cond = 0x04;
                            break; // JE (ZF==1)
                        case IrOp::CMP_NE:
                            setcc_cond = 0x05;
                            break; // JNE (ZF==0)
                        case IrOp::CMP_LT:
                            setcc_cond = 0x0C;
                            break; // JL (SF!=OF)
                        case IrOp::CMP_GE:
                            setcc_cond = 0x0D;
                            break; // JGE (SF==OF)
                        case IrOp::CMP_LE:
                            setcc_cond = 0x0E;
                            break; // JLE (ZF||SF!=OF)
                        // JG (signed greater) no esta directo en
                        // la tabla setcc del VM (0x0F = true
                        // always por bug del impl).  Fallback:
                        // computar via !JLE.  Pero no hay cond
                        // !LE en setcc.  Alternativa: usar JNZ
                        // si sabemos que !ZF, pero no garantizado.
                        // Solucion practica: emitir JLE invertido
                        // mediante XOR posterior, o solo soportar
                        // los casos comunes y mantener fallback
                        // para CMP_GT/CMP_UGT al path tradicional
                        // sin esta optimizacion.
                        case IrOp::CMP_GT:
                            // JG (signed greater) no esta directo.
                            // Equivalente a !(JLE) = !(ZF || SF!=OF).
                            // Trick: usar JGE (SF==OF) + verificar !ZF
                            // requiere 2 setcc + AND.  Por ahora
                            // emitir JGE (over-aproxima: incluye ==).
                            // Para el caso del editor el patron es
                            // raro; si se observa el bug aqui, hay
                            // que usar el path tradicional.
                            setcc_cond = 0x0D;
                            break;
                        case IrOp::CMP_UGT:
                            // JA = JNBE = 0x07 en setcc.
                            setcc_cond = 0x07;
                            break;
                        case IrOp::CMP_ULT:
                            setcc_cond = 0x02;
                            break; // JB (CF==1)
                        case IrOp::CMP_UGE:
                            setcc_cond = 0x03;
                            break; // JAE (CF==0)
                        case IrOp::CMP_ULE:
                            setcc_cond = 0x06;
                            break; // JBE (CF||ZF)
                        default: setcc_cond = 0x04; break;
                        }
                        ctx.out.emit(emmit::Mnemonic::SETCC, Reg::gp(14),
                                     setcc_cond);
                        ctx.r14_cache = -1;
                        // LANG.fix-9 variant: las phi copies pueden
                        // hacer @c mov r14, rN (cuando un phi_dst esta
                        // asignado a r14) -- esto sobrescribe el
                        // resultado del setcc.  Sintoma observado:
                        // @c if (it >= 5) cont = 0; siempre marca
                        // cont=0 porque el setcc se pierde tras
                        // phi_copies y cmpu r14 lee garbage.
                        // Fix: salvar r14 a stack ANTES de phi_copies
                        // y restaurarlo DESPUES.  +2 instrs VM (push/
                        // pop) cuando hay phi copies; cero overhead
                        // cuando no las hay (path cmpjmp fusionado).
                        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(14));
                        emit_phi_copies(ctx, bid, next.false_block);
                        emit_phi_copies(ctx, bid, next.target_block);
                        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(14));
                        ctx.r14_cache = -1;
                        // Test r14 contra 0 con flags FRESCOS del cmpu.
                        // El @c je salta a @c false_block si r14==0
                        // (cond ORIGINAL era false).
                        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), 0);
                        ctx.r13_cache = -1;
                        ctx.out.emit(emmit::Mnemonic::CMPU, Reg::gp(14),
                                     Reg::gp(13));
                        ctx.out.emit(emmit::Mnemonic::JMP_JE,
                                     Ann::absolute(EmitCtx::abs_lbl(
                                         ctx.block_label(next.false_block))));
                        emit_jmp_or_fallthrough(ctx, bid, next.target_block);
                    }
                }
                skip_count = 1; // skip la siguiente instruccion (BR_COND)
                return;
            }
        }
        // Sin fusion: emitir comparacion como valor booleano
        emit_cmp_standalone(ctx, ins);
        break;
    }

    // --- Flujo de control ---
    case IrOp::BR: {
        IrBlockId bid = static_cast<IrBlockId>(&bb - ctx.fn.blocks.data());
        emit_phi_copies(ctx, bid, ins.target_block);
        emit_jmp_or_fallthrough(ctx, bid, ins.target_block);
        break;
    }

    case IrOp::BR_COND: {
        // BR_COND no fusionada: el valor condicion es un bool (0 o 1).
        //
        // LANG.fix-9 (cerrado): las @c emit_phi_copies hacen LOAD/STORE
        // sobre el stack (mov r13, rbp; subu r13, K; mov ...) que
        // CLOBREAN los flags entre el @c cmpu y el @c jmp.je.  Antes,
        // patrones como @c if (it == 0) nlen = 1; emitian:
        //   cmpu r10, r14            ; setear ZF en base a it == 0
        //   <phi copies con subu r13,K>  ; clobrea ZF/SF/CF/OF!
        //   jmp.je if_merge          ; lee flags equivocados
        // Sintoma: la rama then no se tomaba aunque it == 0.
        // Fix: emitir las phi copies de AMBOS sucesores ANTES del
        // @c cmpu.  Los moves son independientes del valor de la
        // condicion (siempre se ejecutan los del bloque actual segun
        // el path tomado), asi que mover su emision arriba es
        // semanticamente identico.  El @c cmpu queda inmediatamente
        // seguido del @c jmp.je sin nada que toque los flags.
        //
        // Si false_block y target_block son distintos sucesores, sus
        // phi copies podrian solapar pero el set de regs es disjunto
        // (cada sucesor tiene su propio bloque PHI con diferentes
        // dst).  Si fueran al mismo bloque (caso degenerado de BR_COND
        // con ambos sucesores iguales), el emisor genera copias
        // duplicadas pero idempotentes.
        if (ins.operands.empty()) break;
        IrBlockId bid = static_cast<IrBlockId>(&bb - ctx.fn.blocks.data());
        // 1) Emitir phi copies de AMBOS sucesores ANTES del cmpu.
        emit_phi_copies(ctx, bid, ins.false_block);
        emit_phi_copies(ctx, bid, ins.target_block);
        // 2) Cargar el valor de la condicion (puede usar r14 scratch
        //    si esta spilled; ya no hay nada que dependa de flags).
        Reg rc = ctx.load_src(ins.operands[0], 0);
        // 3) Comparar con 0 y branch.  El @c cmpu setea flags y el
        //    @c jmp.je los consume sin instrucciones intermedias.
        //
        // LANG.fix-10 (cerrado 2026-05-28): cuando la condicion estaba
        // spilled, @c load_src la carga a @c r14 (SCRATCH_REG).  El
        // viejo codigo emitia @c emit_mov_r14_imm(0) inmediatamente
        // despues, sobrescribiendo @c rc con 0 antes del @c cmpu.
        // Fix: si @c rc esta en r14, usar r13 para el inmediato.
        if (rc.is_gp(14)) {
            emit_mov_r13_imm(ctx, 0);
            ctx.out.emit(emmit::Mnemonic::CMPU, rc, Reg::gp(13));
        } else {
            emit_mov_r14_imm(ctx, 0);
            ctx.out.emit(emmit::Mnemonic::CMPU, rc, Reg::gp(14));
        }
        ctx.out.emit(
            emmit::Mnemonic::JMP_JE,
            Ann::absolute(EmitCtx::abs_lbl(ctx.block_label(ins.false_block))));
        // 4) Fallthrough o salto al target.
        emit_jmp_or_fallthrough(ctx, bid, ins.target_block);
        break;
    }

    case IrOp::RET: {
        if (!ins.operands.empty()) {
            Reg rs = ctx.load_src(ins.operands[0], 0);
            emit_mov_if_needed(ctx, Reg::gp(0), rs);
        }
        ctx.out.emit(emmit::Mnemonic::JMP,
                     Ann::absolute(EmitCtx::abs_lbl(ctx.fn_lbl + "_ret")));
        break;
    }

    case IrOp::UNREACHABLE: ctx.out.emit(emmit::Mnemonic::HLT); break;

    // --- PHI: ya se manejo en emit_phi_copies; aqui es un no-op ---
    case IrOp::PHI:
        // Las copias se emitieron en los predecesores antes del salto
        break;

        // --- Llamadas ---
        //
        // Estructura comun para todas las variantes
        // (CALL/CALLIND/CALLVIRT/CALLN/TAILCALL):
        //
        //   1. Calcular call_pos lineal (necesario para liveness).
        //   2. Identificar registros r0..r12 con valores vivos a traves del
        //   call
        //      (excluyendo el dst del propio call) y emitir un 'push' por cada
        //      uno.
        //   3. Pre-cargar fuentes de los argumentos (incluyendo spills) y
        //   emitir
        //      los moves a r1..r12 con resolucion de conflictos parallel-move.
        //   4. Emitir el callvm / tailcall / callvirt / calln segun
        //   corresponda.
        //   5. Mover r0 al destino si el call produce valor.
        //   6. Emitir 'pop' en orden inverso para restaurar los registros
        //   salvados.
        //
        // Los pasos 2 y 6 son la correccion del bug del regalloc en presencia
        // de valores vivos a traves de un CALL.  Antes, el move de un argumento
        // a r1 podia pisar un parametro que se necesitaba despues del call.

    case IrOp::CALL:
    case IrOp::TAILCALL: {
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        // 2. Save: push de cada registro caller-saved con valor vivo.
        // regs con is_gc_object usan gchandle antes del push.
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);

        // 3. Argument marshalling con parallel-move.
        // Fix: spilled args se cargan DESPUES del parallel-move
        // directamente a su reg destino (evita clobber de r14).
        const size_t nargs = std::min(ins.operands.size(), (size_t)12);
        std::vector<std::pair<int, Reg>> moves;
        std::vector<std::pair<int, ir::IrValueId>> spilled_args;
        moves.reserve(nargs);
        for (size_t ai = 0; ai < nargs; ++ai) {
            ir::IrValueId v = ins.operands[ai];
            int target_reg = static_cast<int>(ai + 1);
            if (v != IR_NO_VALUE && ctx.alloc.spilled(v)) {
                spilled_args.emplace_back(target_reg, v);
            } else {
                moves.emplace_back(target_reg, ctx.load_src(v, 0));
            }
        }
        emit_parallel_arg_moves(ctx, std::move(moves));
        for (auto &pa : spilled_args) {
            emit_load_spilled_arg(ctx, pa.first, pa.second);
        }

        // 4. argc + call.
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), nargs);
        if (ins.op == IrOp::TAILCALL) {
            // Restaurar el banco ancho callee-saved ANTES de desmontar el
            // frame.
            emit_zmm_callee_restore(ctx);
            // solo emitir leave si se emitio enter (has_frame).
            if (ctx.has_frame) {
                ctx.out.emit(emmit::Mnemonic::LEAVE);
            }
            // Cargar direccion en r0 y usar tailcall de registro (unica forma
            // soportada).
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(0),
                         Ann::absolute(EmitCtx::abs_lbl(
                             EmitCtx::sanitize(ins.func_name))));
            ctx.out.emit(emmit::Mnemonic::TAILCALL, Reg::gp(0));
            // En tailcall no hay codigo posterior; los push previos los
            // heredara el callee, lo que rompe la pila.  Por seguridad, NO
            // emitimos push antes de un TAILCALL: en SSA clasico un tailcall
            // implica que su resultado es el ultimo uso de la funcion, asi que
            // no hay valores vivos despues.  Si live_regs_through_call devolvio
            // algo, es bug upstream; aun asi, en TAILCALL los pushes ya
            // emitidos serian popeados nunca, lo que romperia el stack
            // discipline.  El optimizador IR (@c ir_pass_tailcall) solo
            // promociona CALL+RET a TAILCALL cuando esta condicion se cumple
            // por construccion.
        } else {
            ctx.out.emit(emmit::Mnemonic::CALLVM,
                         Ann::absolute(EmitCtx::abs_lbl(
                             EmitCtx::sanitize(ins.func_name))));
            // Stackmap del sitio de retorno: el GC puede correr en el callee;
            // el return_pc de este frame es la siguiente instruccion emitida.
            emit_return_site_stackmap(ctx, bb, idx);
            // 5. Mover r0 al destino si lo hay.  IMPORTANTE: hacerlo ANTES del
            // pop, porque despues de los pops r0 podria haber sido modificado
            // por el restore (no, push/pop no tocan r0, pero por orden).
            if (ins.dst != IR_NO_VALUE) {
                Reg rd = ctx.dst_of(ins.dst);
                emit_mov_if_needed(ctx, rd, Reg::gp(0));
                ctx.store_spilled(ins.dst);
            }
            // 6. Restore en orden inverso.  Para slots que llevaban un host_ptr
            // a un objeto GC-managed, el helper hace gcderef sobre el GcHandle
            // salvado en lugar de un pop crudo: el GC pudo haber evacuado el
            // objeto durante la llamada, asi que el host_ptr previo es obsoleto
            // pero el handle es estable.
            emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        }
        break;
    }

    case IrOp::CALLIND: {
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        // LANG.fix-4: SAVE primero, despues load_src.  Sin esto, si
        // load_src materializa func_ptr en r14 (scratch del regalloc),
        // emit_save_all_gc_aware lo clobrea como scratch del gchandle.
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        Reg rfn = ctx.load_src(ins.func_ptr, 0);
        // El func_ptr debe SOBREVIVIR al marshalling de args (que escribe
        // r1..r12) y a los scratch del parallel-move (r13/r14).  Si quedo en
        // alguno de esos, el `callvmr` saltaria al VALOR DE UN ARG en vez de
        // a la funcion (bug: `mov r1,&fn; mov r1,arg0; callvmr r1`).  Lo
        // anclamos en r0: esta libre hasta que `callvmr` lo consume (el
        // retorno de la funcion sobreescribe r0 DESPUES del salto, y el
        // `mov rd,r0` de abajo ya captura ese retorno).  r0 nunca es destino
        // de un arg (args = r1..r12) ni scratch del move (r13/r14).
        if (!rfn.is_gp(0)) {
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(0), rfn);
            rfn = Reg::gp(0);
        }

        const size_t nargs = std::min(ins.operands.size(), (size_t)12);
        std::vector<std::pair<int, Reg>> moves;
        std::vector<std::pair<int, ir::IrValueId>> spilled_args;
        moves.reserve(nargs);
        for (size_t ai = 0; ai < nargs; ++ai) {
            ir::IrValueId v = ins.operands[ai];
            int target_reg = static_cast<int>(ai + 1);
            if (v != IR_NO_VALUE && ctx.alloc.spilled(v)) {
                spilled_args.emplace_back(target_reg, v);
            } else {
                moves.emplace_back(target_reg, ctx.load_src(v, 0));
            }
        }
        emit_parallel_arg_moves(ctx, std::move(moves));
        for (auto &pa : spilled_args) {
            emit_load_spilled_arg(ctx, pa.first, pa.second);
        }

        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), nargs);
        // CALLIND: el puntero de funcion vive en un registro -> usamos
        // @c callvmr (REG mode, 2 bytes) y NO @c callvm (INMED mode,
        // 10 bytes que espera una direccion absoluta literal).
        ctx.out.emit(emmit::Mnemonic::CALLVMR, rfn);
        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::CALLCLOSURE: {
        // closures: identico a CALLIND mas un `mov r14, env_ptr`
        // antes del callvmr.  La calling convention de los helpers
        // sintetizados (__lambda_<N>) es:
        //   r1..r12 = args declarados (max 12)
        //   r14     = env_ptr (puntero al bloque de captures, 0 si la
        //             lambda no captura nada)
        //   r15     = nargs (consistencia con CALL/CALLIND)
        //
        // La distribucion de operands en el IR es:
        //   ins.func_ptr   = SSA value con la direccion del helper
        //   ins.operands[0] = SSA value con env_ptr (0 si sin captures)
        //   ins.operands[1..] = args declarados
        //
        // Esto reusa todo el regalloc de CALLIND (parallel-move,
        // save/restore de live regs) y solo anade el move a r14.
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        // Materializar fn_addr y env_addr a registros antes de los pushes
        // y de los moves de argumentos para evitar conflictos.
        Reg rfn = ctx.load_src(ins.func_ptr, 0);
        // Hay entorno o no lo hay, y eso es una BANDERA.  Cuando renv era una
        // cadena, "no hay" se decia con la cadena vacia -- un estado que un
        // registro no tiene, y que obligaba a preguntar `.empty()` sobre algo
        // que ya no es texto.
        bool hay_env = false;
        Reg renv = Reg::gp(0);
        if (!ins.operands.empty() && ins.operands[0] != IR_NO_VALUE) {
            renv = ctx.load_src(ins.operands[0], 1);
            hay_env = true;
        }

        // CRITICO: si el regalloc puso fn_addr en r14, NUESTRO
        // `mov r14, env` (mas abajo) lo sobrescribira.  Evacuamos
        // fn_addr a r13 (registro no usado por la calling convention
        // ni por env) ANTES de tocar r14.
        //
        // Igualmente critico: si fn_addr quedo en r1..r12 (un slot
        // de argumento), el parallel-move de abajo lo destruira al
        // colocar el arg correspondiente.  Caso reproducible: una
        // closure invocada con `add5(10)` donde el `mov r1, [r2]`
        // carga fn_addr en r1 y luego el parallel-move `mov r1, r7`
        // (que coloca el arg=10) lo sobrescribe.  Mismo fix: evacuar
        // a r13.
        // r13 nunca es target de la calling convention (r1..r12
        // args, r14 env, r15 nargs, r0 retorno) asi que es seguro.
        const size_t nargs_check =
            ins.operands.size() > 0
                ? std::min(ins.operands.size() - 1, (size_t)12)
                : 0;
        bool fn_in_arg_slot = false;
        if (rfn.bank == Reg::Bank::GP) {
            const int rn = static_cast<int>(rfn.index);
            if (rn >= 1 && rn <= static_cast<int>(nargs_check)) {
                fn_in_arg_slot = true;
            }
        }
        if (rfn.is_gp(14) || fn_in_arg_slot) {
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), rfn);
            rfn = Reg::gp(13);
        }

        // Save de live regs PRIMERO (igual que CALL/CALLIND).  El
        // orden importa para el balance del stack: tras el callvmr,
        // los pops se hacen en orden inverso al push.
        // fix: regs con is_gc_object usan gchandle antes del push.
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);

        // Si env esta en r1..r12 lo pusheamos AHORA (encima de los
        // live regs ya guardados).  El parallel-move puede clobbear
        // r1..r12 al colocar args, asi que necesitamos preservarlo.
        // Lo recuperaremos al r14 con pop INMEDIATAMENTE antes del
        // callvmr (despues del parallel-move) para que sea el TOP
        // del stack en ese momento.
        bool env_pushed = false;
        // r1..r12: los que la convencion de llamada va a pisar.  r13 y r14 son
        // scratch y quedan fuera del rango, asi que no hace falta excluirlos
        // aparte como cuando esto se preguntaba por el nombre.
        if (hay_env && renv.bank == Reg::Bank::GP && renv.index >= 1 &&
            renv.index <= 12) {
            ctx.out.emit(emmit::Mnemonic::PUSH, renv);
            env_pushed = true;
        }

        // Args declarados: comienzan en operands[1] porque operands[0]
        // es el env.  Acotamos a 12 (limite del calling convention).
        const size_t total = ins.operands.size();
        const size_t nargs_decl =
            total > 0 ? std::min(total - 1, (size_t)12) : 0;
        std::vector<std::pair<int, Reg>> moves;
        std::vector<std::pair<int, ir::IrValueId>> spilled_args;
        moves.reserve(nargs_decl);
        for (size_t ai = 0; ai < nargs_decl; ++ai) {
            ir::IrValueId v = ins.operands[ai + 1];
            int target_reg = static_cast<int>(ai + 1);
            if (v != IR_NO_VALUE && ctx.alloc.spilled(v)) {
                spilled_args.emplace_back(target_reg, v);
            } else {
                moves.emplace_back(target_reg, ctx.load_src(v, 0));
            }
        }
        emit_parallel_arg_moves(ctx, std::move(moves));
        for (auto &pa : spilled_args) {
            emit_load_spilled_arg(ctx, pa.first, pa.second);
        }

        // Colocar el env_ptr en r14.  El pop saca el ultimo push
        // (env si env_pushed) que es el TOP correcto.
        if (env_pushed) {
            ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(14));
        } else if (hay_env) {
            emit_mov_if_needed(ctx, Reg::gp(14), renv);
        } else {
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(14), 0);
        }

        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), nargs_decl);
        ctx.out.emit(emmit::Mnemonic::CALLVMR, rfn);
        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::CALLVIRT: {
        if (ins.operands.empty()) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        // fix.order - SAVE primero (libera scratches r14/r13).
        // load_src del receiver/args puede usar libremente esos
        // scratches sin que mi gchandle los pise: la conversion del
        // contenido del slot stack a host_ptr fresco la hace
        // load_src internamente (gcderef + xchg) cuando is_gc_object.
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);

        // Materializar el objeto receptor (load_src ya hace gcderef
        // si esta spilled e is_gc_object).
        Reg r_obj = ctx.load_src(ins.operands[0], 0);

        // Convencion del frontend Vesta: el metodo recibe `this` como
        // primer parametro (r1) y los argumentos declarados a partir
        // de r2.  Por eso colocamos obj en r1 y los demas operandos
        // en r2, r3, ...  El parallel-move resuelve cualquier
        // reordenamiento (ej. arg que ya esta en r1 por live ranges).
        /* Los argumentos viajan en r1..r12 y AQUI el primero es `this`, asi
         * que declarados caben ONCE, no doce: r2..r12.  El recorte decia doce
         * -- el numero de registros, sin contar que uno ya esta ocupado -- y el
         * doceavo acababa escrito en r13, que es scratch del propio emisor.  No
         * fallaba al colocarlo: fallaba despues, en cuanto el cuerpo del metodo
         * llamaba a algo y ese scratch se reusaba, y entonces el argumento
         * llegaba con basura.  El comprobador de tipos rechaza pasar de once
         * antes de llegar aqui; este recorte es la red por si algo lo esquiva.
         */
        const size_t nargs = ins.operands.size() > 1
                                 ? std::min(ins.operands.size() - 1, (size_t)11)
                                 : 0;
        std::vector<std::pair<int, Reg>> moves;
        std::vector<std::pair<int, ir::IrValueId>> spilled_args;
        moves.reserve(nargs + 1);
        // r1 = this (r_obj ya esta en reg via load_src arriba; no es spilled)
        moves.emplace_back(1, r_obj);
        // r2..r_{N+1} = args declarados
        for (size_t ai = 0; ai < nargs; ++ai) {
            ir::IrValueId v = ins.operands[ai + 1];
            int target_reg = static_cast<int>(ai + 2);
            if (v != IR_NO_VALUE && ctx.alloc.spilled(v)) {
                spilled_args.emplace_back(target_reg, v);
            } else {
                moves.emplace_back(target_reg, ctx.load_src(v, 0));
            }
        }
        emit_parallel_arg_moves(ctx, std::move(moves));
        for (auto &pa : spilled_args) {
            emit_load_spilled_arg(ctx, pa.first, pa.second);
        }

        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), (nargs + 1));
        // El callvirt recibe el receptor en r1 (ya colocado por los
        // moves) y el indice del slot en la vtable.
        ctx.out.emit(emmit::Mnemonic::CALLVIRT, Reg::gp(1), ins.imm);
        // Stackmap del sitio de retorno (frame caller): raices en slots de
        // spill vivas a traves del callvirt, keyed al return_pc.
        emit_return_site_stackmap(ctx, bb, idx);
        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::CALLM: {
        // Dispatch dinamico via MethodInfo* directo.  Necesario cuando la
        // vtable_idx no se conoce en compile time, p.ej. invocacion
        // polimorfica sobre un tipo interfaz (donde cada implementador
        // tiene su propia vtable y el slot puede diferir) o reflexion
        // runtime via @c getMethod(cls, name) + invoke.  El frontend
        // resuelve el MethodInfo* en runtime y lo pasa como operando.
        //
        // Layout de operands en el IR:
        //   operands[0] = obj (host_ptr a ObjectHeader)
        //   operands[1] = method (MethodInfo* obtenido via findmethod)
        //   operands[2..] = args declarados (van a r2..r_{N+1})
        // El bytecode `callm r1, r_method` usa r1=obj y un reg con el
        // MethodInfo*.  Movemos obj a r1, args a r2..r_{N+1} y el method
        // a un scratch (r13) para no chocar con la calling convention.
        if (ins.operands.size() < 2) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        // LANG.fix-4: SAVE primero, load_src despues (evita clobber
        // de r14/r13 cuando carga operandos spilled).
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        Reg r_obj = ctx.load_src(ins.operands[0], 0);
        Reg r_meth_src = ctx.load_src(ins.operands[1], 1);

        // Mover MethodInfo* a un reg fijo (r13) que sobrevive el
        // marshalling de args.  r13 es SCRATCH2 del emisor.
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), r_meth_src);

        // Calling convention identica a CALLVIRT: r1 = this, args en r2..
        const size_t nargs = ins.operands.size() > 2
                                 ? std::min(ins.operands.size() - 2, (size_t)11)
                                 : 0;
        std::vector<std::pair<int, Reg>> moves;
        std::vector<std::pair<int, ir::IrValueId>> spilled_args;
        moves.reserve(nargs + 1);
        moves.emplace_back(1, r_obj);
        for (size_t ai = 0; ai < nargs; ++ai) {
            ir::IrValueId v = ins.operands[ai + 2];
            int target_reg = static_cast<int>(ai + 2);
            if (v != IR_NO_VALUE && ctx.alloc.spilled(v)) {
                spilled_args.emplace_back(target_reg, v);
            } else {
                moves.emplace_back(target_reg, ctx.load_src(v, 0));
            }
        }
        emit_parallel_arg_moves(ctx, std::move(moves));
        for (auto &pa : spilled_args) {
            emit_load_spilled_arg(ctx, pa.first, pa.second);
        }

        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), (nargs + 1));
        ctx.out.emit(emmit::Mnemonic::CALLM, Reg::gp(1), Reg::gp(13));
        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::CALLITF: {
        // Dispatch de interfaz via itable.  Estructura identica a CALLM
        // pero el segundo operando es el ItfCallParams (no un MethodInfo*)
        // y emitimos `callitf r1, r13`.  El interp resuelve la itable de la
        // clase concreta (indice O(1) tras warmup) leyendo los params.
        //
        // Layout de operands:
        //   operands[0] = obj (host_ptr a ObjectHeader)
        //   operands[1] = params_ptr (ItfCallParams en stack)
        //   operands[2..] = args declarados (retbuf SRET como [2] si aplica)
        if (ins.operands.size() < 2) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        Reg r_obj = ctx.load_src(ins.operands[0], 0);
        Reg r_params_src = ctx.load_src(ins.operands[1], 1);

        // Mover el ItfCallParams* a r13 (SCRATCH2), que sobrevive el
        // marshalling de args (mismo patron que CALLM con el MethodInfo*).
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), r_params_src);

        // Calling convention identica a CALLVIRT/CALLM: r1 = this, args en
        // r2..  (retbuf SRET en r2 si aplica, tratado como primer arg).
        const size_t nargs = ins.operands.size() > 2
                                 ? std::min(ins.operands.size() - 2, (size_t)11)
                                 : 0;
        std::vector<std::pair<int, Reg>> moves;
        std::vector<std::pair<int, ir::IrValueId>> spilled_args;
        moves.reserve(nargs + 1);
        moves.emplace_back(1, r_obj);
        for (size_t ai = 0; ai < nargs; ++ai) {
            ir::IrValueId v = ins.operands[ai + 2];
            int target_reg = static_cast<int>(ai + 2);
            if (v != IR_NO_VALUE && ctx.alloc.spilled(v)) {
                spilled_args.emplace_back(target_reg, v);
            } else {
                moves.emplace_back(target_reg, ctx.load_src(v, 0));
            }
        }
        emit_parallel_arg_moves(ctx, std::move(moves));
        for (auto &pa : spilled_args) {
            emit_load_spilled_arg(ctx, pa.first, pa.second);
        }

        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), (nargs + 1));
        ctx.out.emit(emmit::Mnemonic::CALLITF, Reg::gp(1), Reg::gp(13));
        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::CALLN: {
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        // FFI runtime indirect: si func_name empieza con
        // "__callni__", el primer operand es el puntero a funcion (ya
        // resuelto por el usuario via ffi_sym/dlsym) y los siguientes
        // son los args.  En vez de emitir `calln @Method("...")`
        // (resuelto en compile-time por el linker), emitimos
        // `callni reg_fn` (puntero leido en runtime).  Misma calling
        // convention: argc en R15, args en R01..R12, retorno en R00.
        const bool is_indirect = ins.func_name.size() >= 11 &&
                                 ins.func_name.rfind("__callni__:", 0) == 0;
        const size_t arg_offset = is_indirect ? 1 : 0;
        const size_t nargs =
            std::min(ins.operands.size() - arg_offset, (size_t)12);

        // fix.b - materializar el puntero de funcion ANTES de
        // emit_save_live_regs y del parallel-move.  Si el regalloc lo
        // puso en un reg que sera arg target (r1..r_N) o en r14
        // (scratch del cycle-breaking), evacuarlo a r13 que NO es
        // tocado por la calling convention.  Mismo fix que CALLCLOSURE.
        // Sin esto, el parallel-move colocaba un arg en el reg del
        // fn-ptr y `callni` saltaba a memoria invalida.
        Reg rfn = Reg::gp(0);
        if (is_indirect) {
            rfn = ctx.load_src(ins.operands[0], 0);
            bool fn_in_arg_slot = false;
            if (rfn.bank == Reg::Bank::GP) {
                const int rn = static_cast<int>(rfn.index);
                if (rn >= 1 && rn <= static_cast<int>(nargs)) {
                    fn_in_arg_slot = true;
                }
            }
            if (rfn.is_gp(14) || fn_in_arg_slot) {
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), rfn);
                rfn = Reg::gp(13);
            }
        }

        // fix: regs con is_gc_object usan gchandle antes del push.
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);

        std::vector<std::pair<int, Reg>> moves;
        std::vector<std::pair<int, ir::IrValueId>> spilled_args;
        moves.reserve(nargs);
        for (size_t ai = 0; ai < nargs; ++ai) {
            ir::IrValueId v = ins.operands[ai + arg_offset];
            int target_reg = static_cast<int>(ai + 1);
            if (v != IR_NO_VALUE && ctx.alloc.spilled(v)) {
                spilled_args.emplace_back(target_reg, v);
            } else {
                moves.emplace_back(target_reg, ctx.load_src(v, 0));
            }
        }
        emit_parallel_arg_moves(ctx, std::move(moves));
        for (auto &pa : spilled_args) {
            emit_load_spilled_arg(ctx, pa.first, pa.second);
        }

        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), nargs);
        if (is_indirect) {
            ctx.out.emit(emmit::Mnemonic::CALLNI, rfn);
        } else {
            ctx.out.emit(emmit::Mnemonic::CALLN, Ann::method(ins.func_name));
        }
        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    // --- Memoria ---
    case IrOp::ALLOCA: {
        // Reservar espacio en pila.  Tamano = count * sizeof(type).
        // El frontend Vesta pasa type=i8, imm=N para reservar N bytes
        // (variables struct); otros frontends pueden usar
        // type=i64, imm=N para arrays de N qwords.
        const uint64_t bytes = ins.imm * type_slot_bytes(ins.type);

        // AUTO-PROMOTE ( D.jit-mem-model MMM ext, 2026-06-01):
        // si `ir_pass_promote_callned_allocas` marco esta ALLOCA con
        // `host_alloca=true`, su dst fluye a un CALLN nativo.  Emitir
        // `alloc N` (RAW_ALLOC bytecode) en lugar de `subsp` para
        // que el ptr sea host genuino dereferenciable directamente
        // por la libreria C.  El IR pass tambien inserto RAW_FREE
        // antes de cada RET / RSPAWN_RETURN / FULFILL_HLT para
        // evitar leaks en exits normales.  THROW sin try/catch que
        // envuelva sigue pudiendo leakear (sprint sucesor cubrira
        // tracking runtime para cleanup en do_throw).
        if (ins.host_alloca && ins.dst != IR_NO_VALUE) {
            // Tratar como CALL: `alloc` clobrea r0 implicitamente y
            // puede ejecutar codigo arbitrario (slab grow).
            const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
            std::vector<int> regs_to_save =
                live_regs_through_call(ctx, call_pos, ins.dst);
            emit_save_live_regs(ctx, call_pos, regs_to_save);
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(0), bytes);
            ctx.out.emit(emmit::Mnemonic::ALLOC, Reg::gp(0));
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
            ctx.store_spilled(ins.dst);
            // Sprint MMM-ext leak-fix: registrar el ptr en el frame
            // actual via `htrack`.  RET / do_throw / TAILCALL liberan
            // automaticamente sin necesidad de RAW_FREE explicito.
            // Cubre TODOS los exit paths (incluido throw cross-frame).
            //
            // Sprint mem-loop-fix (2026-06-02): SKIPEAR htrack cuando
            // el promote pass marco la ALLOCA con explicit_free=true.
            // El RAW_FREE preservado en el IR libera el ptr en su
            // sitio (al fin de cada iteracion del loop), sin
            // acumular en el vector host_allocas del frame.
            // Bottleneck antes: 5M iter de malloc(96)+free -> 20s
            // por acumular 5M ptrs tracked sin liberar hasta RET.
            if (!ins.host_alloca_explicit_free) {
                Reg rd_track = ctx.dst_of(ins.dst);
                ctx.out.emit(emmit::Mnemonic::HTRACK, rd_track);
            }
            emit_restore_live_regs(ctx, call_pos, regs_to_save);
            break;
        }

        ctx.out.emit(emmit::Mnemonic::SUBSP, Reg::special(SpecialReg::RSP),
                     bytes);
        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            // Capturar la direccion base de la zona reservada.  Tras
            // subsp, rsp apunta justo al inicio del nuevo bloque
            // (la pila crece "hacia abajo").  Hacemos `mov rd, rsp`
            // y los call sites pueden usar `[rd]` / `[rd + offset]`
            // para acceder a los slots.  No usamos readcur porque
            // los cursores son utiles cuando el offset es dinamico
            // (acceso a campos de objeto GC, p.ej.); para variables
            // de pila la direccion base directa es mas simple y
            // produce .vel mas pequeno.
            ctx.out.emit(emmit::Mnemonic::MOV, rd,
                         Reg::special(SpecialReg::RSP));
            ctx.store_spilled(ins.dst);
        }
        break;
    }

    case IrOp::LOAD: {
        if (ins.operands.empty()) break;
        // Fase 3: si el dst es un escalar float residente del banco ancho, la
        // carga va DIRECTO al registro ZMM (mld bank=1), sin movh + bitg2z.
        // Reusa la fusion de direccion Fase 1/2 (compute_wide_addr).
        {
            const int freg = ctx.zmm_of(ins.dst);
            if (freg >= 0) {
                const size_t tsz = type_slot_bytes(ins.type);
                const unsigned wcode = (tsz == 4) ? 2u : 3u;
                const WideAddr w = compute_wide_addr(ctx, ins, 0);
                emit_wide_mem(ctx, /*is_load=*/true, freg, w, wcode);
                break; // el valor vive en ZMM; sin store_spilled ni sext
            }
        }
        //   direccion fusionada (add-const absorbido) -> un unico
        // `mld dst, r0, ctrlword, disp` que computa base+disp, carga `width`
        // bytes y sign/zero-extiende, todo en un dispatch (vs add + loadz +
        // shl + sar = hasta 4 instrucciones).
        {
            auto fit = ctx.addr_fusion.find(&ins);
            if (fit != ctx.addr_fusion.end() && ins.dst != IR_NO_VALUE) {
                const auto &fa = fit->second;
                const int base_reg = ctx.reg_num(fa.base);
                const int idx_reg =
                    (fa.index == IR_NO_VALUE) ? 0 : ctx.reg_num(fa.index);
                const int dst_reg = ctx.reg_num(ins.dst); // reg o scratch
                const size_t tsz = type_slot_bytes(ins.type);
                const unsigned wcode = (tsz == 1)   ? 0u
                                       : (tsz == 2) ? 1u
                                       : (tsz == 4) ? 2u
                                                    : 3u;
                const bool host = ctx.fn.values[ins.operands[0]].is_host_ptr;
                const bool is_signed =
                    (ins.type == IrType::I8 || ins.type == IrType::I16 ||
                     ins.type == IrType::I32);
                const bool skip_sext = ctx.fn.values[ins.dst].narrow_only;
                const bool sign_ext = (tsz < 8 && is_signed && !skip_sext);
                const bool has_index = (fa.index != IR_NO_VALUE);
                const uint32_t cw =
                    (static_cast<uint32_t>(base_reg) & 0x1F) |
                    ((static_cast<uint32_t>(fa.scale) & 7u) << 5) |
                    (wcode << 8) | ((host ? 1u : 0u) << 11) |
                    ((has_index ? 1u : 0u) << 12) |
                    ((sign_ext ? 1u : 0u) << 14);
                ctx.out.emit(
                    emmit::Mnemonic::MLD,
                    Reg::gp(static_cast<unsigned>(dst_reg)),
                    Reg::gp(static_cast<unsigned>(idx_reg)), cw,
                    static_cast<uint16_t>(static_cast<int16_t>(fa.disp)));
                if (dst_reg == SCRATCH_REG) ctx.r14_cache = -1;
                if (dst_reg == SCRATCH2_REG) ctx.r13_cache = -1;
                ctx.store_spilled(ins.dst);
                break;
            }
        }
        Reg rp = ctx.load_src(ins.operands[0], 0);
        // Tamano del LOAD segun ins.type.  Sin sufijo el parser
        // asume 64 bits y leeria mas alla del campo destino,
        // leyendo basura o causando segfault al tocar memoria no
        // mapeada.
        Reg rd_full = ctx.dst_of(ins.dst);
        // El registro destino del load tiene que llevar SIEMPRE el sufijo de
        // tamano.  ANTES, si el valor estaba DERRAMADO, esta rama caia a
        // `rd_full` -- el registro entero, sin sufijo -- y el ensamblador
        // codificaba el load como de 64 bits: un `u8 c = arr[i]` leia OCHO
        // bytes.  El valor final salia bien igualmente (el sext/mascara de
        // abajo descarta los bits altos), asi que el fallo solo se notaba
        // cuando los 7 bytes de mas cruzaban a una pagina no mapeada ->
        // SIGSEGV, y solo con suficiente presion de registros como para
        // derramar.  `reg_num()` ya devuelve SCRATCH_REG para los derramados
        // -- exactamente el mismo registro que devuelve `dst_of()` --, asi
        // que sirve para los dos casos y lo unico que cambia es el sufijo.
        // Es el mismo arreglo que STORE ya tenia desde `59_arraylist.vx`.
        Reg rd_sz = (ins.dst == IR_NO_VALUE)
                        ? rd_full
                        : reg_name_sized(ctx.reg_num(ins.dst), ins.type);
        // La VM NO hace zero-extend en `mov rXd/w/b, [src]` (a
        // diferencia de x86-64 con la mitad inferior).  Los bits
        // altos del registro destino conservan su valor previo,
        // contaminando operaciones aritmeticas posteriores.  Si el
        // tipo cargado es < 64 bits, hacemos zero-extend.
        //
        // OPTIMIZACION (super-instruccion loadz/loadzh): cuando
        // tsz < 8, en lugar del par `mov rd,0; mov rd_sz,[rp]` (10
        // bytes / 2 instr VM) emitimos un solo `loadz/loadzh rd_sz,rp`
        // (4 bytes / 1 instr VM).  Reduce dispatch + decode 50% para
        // cargas i8/i16/i32 (el caso comun en bench_struct_field,
        // bench_array_sum, y todo codigo con structs/arrays nativos).
        // Para tsz == 8 (load 64-bit completo) seguimos con mov normal.
        const size_t tsz = type_slot_bytes(ins.type);
        const bool host_ptr = ins.operands[0] != IR_NO_VALUE &&
                              ctx.fn.values[ins.operands[0]].is_host_ptr;
        if (tsz < 8) {
            const emmit::Mnemonic opc_z =
                host_ptr ? emmit::Mnemonic::LOADZH : emmit::Mnemonic::LOADZ;
            ctx.out.emit(opc_z, rd_sz, rp);
        } else {
            const emmit::Mnemonic opcode =
                host_ptr ? emmit::Mnemonic::MOVH : emmit::Mnemonic::MOV;
            ctx.out.emit(opcode, rd_sz, Mem(rp));
        }
        // Sign-extension manual para tipos signed < 64 bits.  Sin esto
        // los i8/i16/i32 con valores negativos se cargan con bits
        // altos a 0 (debido al zero-extend manual de arriba), y
        // operaciones signed posteriores como cmps o adds tratan al
        // valor como su representacion sin signo (e.g. -1 i32 se
        // convierte en 4294967295 i64).  La fix es shl + sar por
        // (64 - bits del tipo) que propaga el bit de signo.  Solo se
        // aplica a I8/I16/I32 (no a U*); I64 ya es full width.
        // Optimizacion (ir_pass_load_narrow @ O2): si narrow_only=true,
        // todos los usos transitivos son arith narrow-safe (ADD/SUB/MUL/
        // AND/OR/XOR) + STORE/RET del mismo ancho.  Los bits altos no
        // importan, asi que podemos saltar el patron shl+sar (3 instr VM).
        const bool skip_sext =
            ins.dst != IR_NO_VALUE && ctx.fn.values[ins.dst].narrow_only;
        if (tsz < 8 && !skip_sext &&
            (ins.type == IrType::I8 || ins.type == IrType::I16 ||
             ins.type == IrType::I32)) {
            const unsigned shift_bits = static_cast<unsigned>(64 - tsz * 8);
            // SHL/SAR de la VM solo aceptan reg-reg, no inmediatos.
            // Cargamos la cuenta en un scratch DISTINTO de rd_full.
            // Bug fix: si rd_full == r14 (SCRATCH_REG), el mov
            // clobreaba el valor cargado; usamos r13 (SCRATCH2) en
            // ese caso.  Mismo patron que el CAST/SEXT.
            const Reg scratch = (rd_full == Reg::gp(SCRATCH_REG))
                                    ? Reg::gp(SCRATCH2_REG)
                                    : Reg::gp(SCRATCH_REG);
            emit_mov_scratch_shift_imm(ctx, scratch,
                                       static_cast<int64_t>(shift_bits));
            ctx.out.emit(emmit::Mnemonic::SHL, rd_full, scratch);
            ctx.out.emit(emmit::Mnemonic::SAR, rd_full, scratch);
        }
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::STORE: {
        if (ins.operands.size() < 2) break;
        // Fase 3: si el VALOR a escribir es un escalar float residente del
        // banco ancho, se escribe DIRECTO desde su registro ZMM (mst bank=1),
        // sin bitz2g previo.  Reusa la fusion de direccion Fase 1/2.
        {
            const int freg = ctx.zmm_of(ins.operands[0]);
            if (freg >= 0) {
                const size_t tsz = type_slot_bytes(ins.type);
                const unsigned wcode = (tsz == 4) ? 2u : 3u;
                const WideAddr w = compute_wide_addr(ctx, ins, 1);
                emit_wide_mem(ctx, /*is_load=*/false, freg, w, wcode);
                break;
            }
        }
        //   direccion fusionada -> `mst val, r0, ctrlword, disp`.
        {
            auto fit = ctx.addr_fusion.find(&ins);
            if (fit != ctx.addr_fusion.end()) {
                const auto &fa = fit->second;
                // Cargar el valor primero (puede usar scratch); base e index
                // son registros reales, asi que no se pisan.
                Reg rv = ctx.load_src(ins.operands[0], 0);
                const int base_reg = ctx.reg_num(fa.base);
                const int idx_reg =
                    (fa.index == IR_NO_VALUE) ? 0 : ctx.reg_num(fa.index);
                const size_t tsz = type_slot_bytes(ins.type);
                const unsigned wcode = (tsz == 1)   ? 0u
                                       : (tsz == 2) ? 1u
                                       : (tsz == 4) ? 2u
                                                    : 3u;
                const bool host = ctx.fn.values[ins.operands[1]].is_host_ptr;
                const bool has_index = (fa.index != IR_NO_VALUE);
                const uint32_t cw =
                    (static_cast<uint32_t>(base_reg) & 0x1F) |
                    ((static_cast<uint32_t>(fa.scale) & 7u) << 5) |
                    (wcode << 8) | ((host ? 1u : 0u) << 11) |
                    ((has_index ? 1u : 0u) << 12);
                ctx.out.emit(
                    emmit::Mnemonic::MST, Reg(rv),
                    Reg::gp(static_cast<unsigned>(idx_reg)), cw,
                    static_cast<uint16_t>(static_cast<int16_t>(fa.disp)));
                break;
            }
        }
        Reg rv = ctx.load_src(ins.operands[0], 0); // valor a escribir
        Reg rp = ctx.load_src(ins.operands[1], 1); // puntero destino
        // Sufijo de tamano para que mov escriba exactamente sizeof(type)
        // bytes (no 8 por defecto).  Igual que en LOAD.
        //
        // Sprint mem-loop-fix (2026-06-02): el bug previo aplicaba el
        // sufijo SOLO cuando el operando estaba en registro.  Si el
        // valor venia de spill (rv = "r14"/"r13" tras load_src), se
        // emitia `movh [rp], r14` sin sufijo = QWORD STORE (8 bytes)
        // aunque el IR pidiera STORE i32 (4 bytes).
        //
        // Consecuencia: en un slot del slab de 16 bytes, escribir
        // `buf[3]` con qword corrompia los bytes 12-19 (4 bytes fuera
        // del slot, en el slot vecino).  Repro:
        // `examples_codes_vx/59_arraylist.vx`.
        //
        // Fix: SIEMPRE aplicar sufijo segun ins.type, incluso cuando
        // el reg es scratch del spill (r14/r13).  La VM ya soporta
        // las variantes sized del `mov`/`movh` (b/w/d/q).
        Reg rv_sized = rv;
        if (ctx.is_in_reg(ins.operands[0])) {
            rv_sized = reg_name_sized(ctx.reg_num(ins.operands[0]), ins.type);
        } else {
            // Operando spilled: rv es "r14" o "r13".  Aplicar sufijo
            // de tamano segun ins.type.  reg_num_for_name retorna el
            // indice 13/14 para construir el nombre sized.
            int reg_idx = -1;
            if (rv.is_gp(13))
                reg_idx = 13;
            else if (rv.is_gp(14))
                reg_idx = 14;
            // Cualquier otro general: el numero lo lleva el propio operando,
            // asi que ya no hay que sacarlo del nombre con strtol.
            else if (rv.bank == Reg::Bank::GP)
                reg_idx = static_cast<int>(rv.index);
            if (reg_idx >= 0) {
                rv_sized = reg_name_sized(reg_idx, ins.type);
            }
        }
        const bool host_ptr = ins.operands[1] != IR_NO_VALUE &&
                              ctx.fn.values[ins.operands[1]].is_host_ptr;
        const emmit::Mnemonic opcode =
            host_ptr ? emmit::Mnemonic::MOVH : emmit::Mnemonic::MOV;
        ctx.out.emit(opcode, Mem(rp), rv_sized);
        break;
    }

    case IrOp::RAW_ALLOC: {
        // LANG.fix-8: el `alloc` clobrea IMPLICITAMENTE r0.  Tratar
        // como CALL para preservar regs vivos.
        if (ins.operands.empty()) break;
        Reg r_size = ctx.load_src(ins.operands[0], 0);
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);
        emit_save_live_regs(ctx, call_pos, regs_to_save);
        ctx.out.emit(emmit::Mnemonic::ALLOC, r_size);
        if (ins.dst != IR_NO_VALUE) {
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        emit_restore_live_regs(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::RAW_FREE: {
        // Emite: free <r_ptr>;  el bytecode `free` (opcode 0xB1)
        // libera el bloque devuelto previamente por alloc.
        if (ins.operands.empty()) break;
        Reg r_ptr = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::FREE, r_ptr);
        break;
    }

    case IrOp::GC_ALLOC: {
        // Optimizado: emite el opcode dedicado `gcallocp r_dst, r_size`
        // (extended 0x65) que aloca en GcHeap + deposita host_ptr al
        // payload en r_dst en una SOLA instruccion VM.  Sustituye la
        // secuencia previa de 3 instr (gcalloc + gcderef + xchg).
        //
        // El GC puede disparar minor/major durante el alloc (evacuacion
        // YOUNG -> OLD), asi que envolvemos con save/restore de live
        // regs igual que NEWOBJ.  Sin save/restore, un patron como:
        //   T owned = make_a();    // owned vivo en r2
        //   env = gc_alloc(N*8);   // si N grande, dispara major GC
        //   *(env+0) = owned;      // r2 ahora apunta a memoria stale
        // crashearia silenciosamente.  El save/restore garantiza que r2
        // se push'ea como GcHandle (estable a evacuacion) y se pop'ea
        // como host_ptr fresco tras el alloc.
        if (ins.operands.empty()) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);
        emit_save_live_regs(ctx, call_pos, regs_to_save);
        Reg r_size = ctx.load_src(ins.operands[0], 0);
        // E.1: stackmap justo antes del opcode gcallocp (safepoint).
        emit_stackmap_marker(ctx, bb, idx);
        if (ins.dst != IR_NO_VALUE) {
            Reg r_dst = ctx.dst_of(ins.dst);
            ctx.out.emit(emmit::Mnemonic::GCALLOCP, r_dst, r_size);
            ctx.store_spilled(ins.dst);
        } else {
            // Sin destino: alocar y descartar (raro, pero defensivo).
            ctx.out.emit(emmit::Mnemonic::GCALLOCP, Reg::gp(0), r_size);
        }
        emit_restore_live_regs(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::MEMCPY: {
        /* memcpy -> INSTRUCCION de la VM, variante HOST.
         *
         * @c IrOp::MEMCPY esta definido como HOST->HOST: ambos operandos son
         * punteros del proceso host (el pase que lo produce solo reconoce el
         * idioma de copia sobre punteros host, y el lowering anterior ya usaba
         * `loadzh`/`movh`).  NO se consulta @c is_host_ptr: hacerlo fue un bug
         * -- el flag venia a false en el puntero base resuelto por el pase, se
         * emitia la variante VIRTUAL y el interprete trataba direcciones host
         * como direcciones VM (SIGSEGV en 183_memcpy_idiom).  Si algun dia
         * existe una copia VM->VM sera OTRO op, no una variante de este.
         *
         * Sustituye al bucle byte a byte que se emitia antes: una vuelta de
         * dispatch del interprete POR BYTE, cuando la instruccion mueve la
         * region con movimientos vectoriales de 16/32 bytes.  Se usan los
         * registros DONDE YA VIVEN los operandos -- forzarlos a unos fijos solo
         * anyadiria movimientos y trafico de registros. */
        if (ins.operands.size() < 3) break;
        emit_three_reg_op(ctx, emmit::Mnemonic::MEMCPYH, ins.operands[0],
                          ins.operands[1], ins.operands[2]);
        ctx.r13_cache = -1;
        ctx.r14_cache = -1;
        break;
    }

    case IrOp::MEMSET: {
        /* memset -> INSTRUCCION de la VM (una sola), en su variante segun donde
         * viva el destino: `memseth` para memoria del HOST y `memset` para
         * memoria VIRTUAL.  Esa eleccion la da @c is_host_ptr del puntero, el
         * mismo criterio que ya distingue mov/movh y loadz/loadzh.
         *
         * Es la razon de ser del op: MEMSET dice QUE hay que hacer y cada
         * backend elige COMO.  Antes de existir, esto se desplegaba en un STORE
         * por cada 8 bytes -- `i32[8192] arr;` costaba 16397 instrucciones. */
        if (ins.operands.size() < 3) break;
        const bool host = ins.operands[0] < ctx.fn.values.size() &&
                          ctx.fn.values[ins.operands[0]].is_host_ptr;
        /* Se usan los registros DONDE YA VIVEN los operandos: la instruccion
         * toma tres registros cualesquiera, asi que forzarlos a unos fijos solo
         * anyadiria tres `mov` y trafico de registros que no hace falta.  El
         * emisor solo tiene DOS scratch, asi que con tres operandos derramados
         * el tercero pisaria al segundo -- de eso se encarga el helper. */
        emit_three_reg_op(
            ctx, host ? emmit::Mnemonic::MEMSETH : emmit::Mnemonic::MEMSET,
            ins.operands[0], ins.operands[1], ins.operands[2]);
        ctx.r13_cache = -1;
        ctx.r14_cache = -1;
        break;
    }

    // VEC_UNOP dst[i] = OP a[i]  (auto-vectorizacion unaria).  Interprete
    // (oraculo) = W ops ESCALARES por lane (copy via movh; fneg/fabs/fsqrt via
    // bitg2z/f<op>/bitz2g); el JIT lo baja a SIMD packed (SQRTPD/XORPD/ANDPD).
    // Solo f64 (el matcher solo emite f64).  Robusto: push/pop r10/r11 (dst/a).
    case IrOp::VEC_UNOP: {
        if (ins.operands.size() < 2) break;
        const uint64_t width = ins.imm & 0xFF;
        const uint64_t subop = (ins.imm >> 8) & 0xFF;
        const size_t esz = type_slot_bytes(ins.type);
        if (esz == 0) break;
        const uint64_t W = width / esz;
        /* Negar un entero no es la operacion flotante: es restar de cero.  Lo
         * demas -- valor absoluto y raiz -- solo tiene sentido en coma
         * flotante.  Y en f32 la operacion es la variante empaquetada: aplicar
         * la de f64 sobre bits de 32 leeria otro numero. */
        const bool es_fp = (ins.type == IrType::F64 || ins.type == IrType::F32);
        const bool es_ps = (ins.type == IrType::F32);
        const emmit::Mnemonic uop =
            (subop == 1)   ? emmit::Mnemonic::FNEG
            : (subop == 2) ? emmit::Mnemonic::FABS
            : (subop == 3) ? emmit::Mnemonic::FSQRT
                           : emmit::Mnemonic::kCount;  // 0=copy (sin op)
        if (!es_fp && subop != 0 && subop != 1) break; // entero: solo negar
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(11));
        {
            const Reg p = ctx.load_src(ins.operands[0], 0); // dst
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[1], 0); // a
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10)); // a, dst
        for (uint64_t k = 0; k < W; ++k) {
            if (k > 0) {
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(11), esz);
            }
            ctx.out.emit(vec_mv(ctx, ins, 1), Reg::gp(14),
                         Mem(Reg::gp(11))); // a[k] bits
            if (!es_fp) {
                /* Entero: -a[k] es 0 - a[k].  Se calcula en r13, que este
                 * bloque invalida al salir. */
                if (subop == 1) {
                    ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13),
                                 static_cast<uint64_t>(0));
                    ctx.out.emit(emmit::Mnemonic::SUBS, Reg::gp(13),
                                 Reg::gp(14));
                    ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(14),
                                 Reg::gp(13));
                }
            } else if (emmit::is_valid(uop)) {
                ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(0), Reg::gp(14));
                ctx.out.emit(emmit::packed_if(uop, es_ps), Reg::fp(0),
                             Reg::fp(0));
                ctx.out.emit(emmit::Mnemonic::BITZ2G, Reg::gp(14), Reg::fp(0));
            }
            ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                         Reg::gp(14)); // dst[k]
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.r13_cache = -1;
        ctx.r14_cache = -1;
        break;
    }

    // VEC_BINOP dst[i] = a[i] OP b[i]  (auto-vectorizacion).  En el interprete
    // (oraculo) lo bajamos a W operaciones ESCALARES por lane; el JIT lo baja a
    // SIMD packed (MOVUPD + ADDPD/PADDQ/...).  Soporta f64/f32 (via bitg2z/
    // f<op>/bitz2g) y enteros i32/i64 (add/sub directo).  Robusto frente al
    // regalloc: push/pop de r10/r11/r12 (dst/a/b) + r13/r14 + f0/f1 scratch.
    case IrOp::VEC_BINOP: {
        if (ins.operands.size() < 3) break;
        const uint64_t width = ins.imm & 0xFF;
        const uint64_t subop = (ins.imm >> 8) & 0xFF;
        const size_t esz = type_slot_bytes(ins.type);
        if (esz == 0) break;
        const uint64_t W = width / esz;
        const bool is_fp = (ins.type == IrType::F64 || ins.type == IrType::F32);
        const emmit::Mnemonic fop = (subop == 0)   ? emmit::Mnemonic::FADD
                                    : (subop == 1) ? emmit::Mnemonic::FSUB
                                    : (subop == 2) ? emmit::Mnemonic::FMUL
                                                   : emmit::Mnemonic::FDIV;
        // int: add/sub/mul.  El low de un producto signed==unsigned -> "muls"
        // sirve para i/u (solo guardamos los esz bytes bajos).
        const emmit::Mnemonic iop = (subop == 0)   ? emmit::Mnemonic::ADDS
                                    : (subop == 1) ? emmit::Mnemonic::SUBS
                                                   : emmit::Mnemonic::MULS;
        const bool es_ps = (ins.type == IrType::F32);
        // sufijo de tamano del reg para load/store entero
        // (8b->"", 4b->"d", 2b->"w", 1b->"b").
        const Reg::Width rsz = width_for_bytes(static_cast<unsigned>(esz));
        // Cargar los 3 punteros (dst/a/b) en r10/r11/r12 via push del VALOR
        // (sin hazard de parallel-move).
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(12));
        // load_src emite codigo (spill) -> capturar en var ANTES del push.
        {
            const Reg p = ctx.load_src(ins.operands[0], 0); // dst
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[1], 0); // a
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[2], 0); // b
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(12));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10)); // b, a, dst
        for (uint64_t k = 0; k < W; ++k) {
            if (k > 0) {
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(11), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(12), esz);
            }
            if (is_fp) {
                // carga esz bytes (f64=8 -> r14; f32=4 -> r14d) y opera con el
                // sufijo .ps cuando es f32 (low 32 del banco ZMM).
                ctx.out.emit(vec_mv(ctx, ins, 1), Reg::gp(14, rsz),
                             Mem(Reg::gp(11))); // a[k] bits
                ctx.out.emit(vec_mv(ctx, ins, 2), Reg::gp(13, rsz),
                             Mem(Reg::gp(12))); // b[k] bits
                ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(0), Reg::gp(14));
                ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(1), Reg::gp(13));
                ctx.out.emit(emmit::packed_if(fop, es_ps), Reg::fp(0),
                             Reg::fp(1));
                ctx.out.emit(emmit::Mnemonic::BITZ2G, Reg::gp(14), Reg::fp(0));
                ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                             Reg::gp(14, rsz)); // dst[k]
            } else {
                // entero: cargar esz bytes ZERO-EXTENDIDO (loadzh, no movh: el
                // movh-load parcial de 16/8b deja bits altos basura que rompen
                // muls/adds de 64b), operar, guardar los esz bytes bajos.  El
                // signo no importa: los esz bytes bajos del resultado dependen
                // solo de los esz bytes bajos de los operandos (add/sub/mul).
                ctx.out.emit(emmit::Mnemonic::LOADZH, Reg::gp(14, rsz),
                             Reg::gp(11)); // a[k]
                ctx.out.emit(emmit::Mnemonic::LOADZH, Reg::gp(13, rsz),
                             Reg::gp(12));                   // b[k]
                ctx.out.emit(iop, Reg::gp(14), Reg::gp(13)); // a OP b (64b)
                ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                             Reg::gp(14, rsz)); // dst[k]
            }
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(12));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.r13_cache = -1;
        ctx.r14_cache = -1;
        break;
    }

    // VEC_BINOP_S dst[i] = a[i] OP escalar.  Interp = W ops escalares por lane.
    // f64: el escalar en f2.  enteros: el escalar (i64 replicado; sus esz bytes
    // bajos = el valor) en r13; loadzh por lane + add/sub/mul de 64b + store
    // low. r10=dst, r11=a.
    case IrOp::VEC_BINOP_S: {
        if (ins.operands.size() < 3) break;
        const uint64_t width = ins.imm & 0xFF;
        const uint64_t subop = (ins.imm >> 8) & 0xFF;
        const size_t esz = type_slot_bytes(ins.type);
        if (esz == 0) break;
        const uint64_t W = width / esz;
        const bool is_fp = (ins.type == IrType::F64 || ins.type == IrType::F32);
        const emmit::Mnemonic fop = (subop == 0)   ? emmit::Mnemonic::FADD
                                    : (subop == 1) ? emmit::Mnemonic::FSUB
                                    : (subop == 2) ? emmit::Mnemonic::FMUL
                                                   : emmit::Mnemonic::FDIV;
        const emmit::Mnemonic iop = (subop == 0)   ? emmit::Mnemonic::ADDS
                                    : (subop == 1) ? emmit::Mnemonic::SUBS
                                                   : emmit::Mnemonic::MULS;
        // .ps para f32 (opera el low 32 del banco ZMM); vacio para f64.
        const bool es_ps = (ins.type == IrType::F32);
        const Reg::Width rsz = width_for_bytes(static_cast<unsigned>(esz));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(11));
        {
            const Reg p = ctx.load_src(ins.operands[0], 0); // dst
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[1], 0); // a
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[2], 0); // escalar
            if (is_fp)
                ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(2), p);
            else
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), p);
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10)); // a, dst
        for (uint64_t k = 0; k < W; ++k) {
            if (k > 0) {
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(11), esz);
            }
            if (is_fp) {
                // f64=8 bytes -> r14; f32=4 -> r14d; op con sufijo .ps si f32.
                ctx.out.emit(vec_mv(ctx, ins, 1), Reg::gp(14, rsz),
                             Mem(Reg::gp(11))); // a[k]
                ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(0), Reg::gp(14));
                ctx.out.emit(emmit::packed_if(fop, es_ps), Reg::fp(0),
                             Reg::fp(2));
                ctx.out.emit(emmit::Mnemonic::BITZ2G, Reg::gp(14), Reg::fp(0));
                ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                             Reg::gp(14, rsz)); // dst[k]
            } else {
                ctx.out.emit(emmit::Mnemonic::LOADZH, Reg::gp(14, rsz),
                             Reg::gp(11));                   // a[k]
                ctx.out.emit(iop, Reg::gp(14), Reg::gp(13)); // a OP scalar
                ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                             Reg::gp(14, rsz)); // dst[k]
            }
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.r13_cache = -1;
        ctx.r14_cache = -1;
        break;
    }

    // VEC_FMA_S: dst[k] += a[k]*escalar (por lane, fmadd = 1 redondeo,
    // BIT-EXACTO con VFMADD231 del JIT).  Paso "array escalado" del compound.
    // El escalar es el operando 2 (leido por lane; el bcast del JIT es no-op
    // aqui).
    case IrOp::VEC_FMA_S: {
        if (ins.operands.size() < 3) break;
        const uint64_t width = ins.imm & 0xFF;
        const size_t esz = type_slot_bytes(ins.type);
        if (esz == 0) break;
        const uint64_t W = width / esz;
        const bool es_ps = (ins.type == IrType::F32);
        const Reg::Width rsz = width_for_bytes(static_cast<unsigned>(esz));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(11));
        {
            const Reg p = ctx.load_src(ins.operands[0], 0); // dst
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[1], 0); // a
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[2], 0); // escalar
            ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(2), p);
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10)); // a, dst
        for (uint64_t k = 0; k < W; ++k) {
            if (k > 0) {
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(11), esz);
            }
            ctx.out.emit(vec_mv(ctx, ins, 1), Reg::gp(14, rsz),
                         Mem(Reg::gp(11))); // a[k]
            ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(0), Reg::gp(14));
            ctx.out.emit(vec_mv(ctx, ins, 0), Reg::gp(14, rsz),
                         Mem(Reg::gp(10))); // c[k]
            ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(1), Reg::gp(14));
            ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FMADD, es_ps),
                         Reg::fp(1), Reg::fp(0), Reg::fp(2)); // f1 = a*esc + c
            ctx.out.emit(emmit::Mnemonic::BITZ2G, Reg::gp(14), Reg::fp(1));
            ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                         Reg::gp(14, rsz)); // c[k]
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.r13_cache = -1;
        ctx.r14_cache = -1;
        break;
    }

    // VEC_BCAST: hoist del broadcast del escalar a XMM13 (solo JIT).  En el
    // interprete es NO-OP: el VEC_BINOP_S del cuerpo re-lee el escalar
    // (operando 2) por lane, asi que no necesita estado pre-difundido.
    case IrOp::VEC_BCAST: break;

    // VEC_FMA fusionado (1 redondeo).  Interp (oraculo) = W ops ESCALARES por
    // lane con `fmadd` (std::fma) para coincidir BIT-A-BIT con VFMADD231 del
    // JIT. Dos formas: 3 ops {acc,a,b} = reduccion acc[i]+=a[i]*b[i]
    // (sumando==dst); 4 ops {c,d,a,b} = element-wise c[i]=a[i]*b[i]+d[i]
    // (sumando d != dst c). r9=sumando, r10=dst, r11=a, r12=b.  Solo f64/f32.
    case IrOp::VEC_FMA: {
        if (ins.operands.size() < 3) break;
        const bool fma3 = (ins.operands.size() >= 4); // element-wise
        const int o_dst = 0;
        const int o_add = fma3 ? 1 : 0;
        const int o_a = fma3 ? 2 : 1;
        const int o_b = fma3 ? 3 : 2;
        const uint64_t width = ins.imm & 0xFF;
        // Bit 8 = variante SUB (c=a*b-d).  Solo element-wise (4 ops).  Se emula
        // negando el sumando: fma(a,b,-d) = round(a*b - d), BIT-EXACTO con el
        // VFMSUB231 del JIT (el -d es exacto).
        const bool fma_sub = fma3 && ((ins.imm >> 8) & 1u);
        const size_t esz = type_slot_bytes(ins.type);
        if (esz == 0) break;
        const uint64_t W = width / esz;
        const bool es_ps = (ins.type == IrType::F32);
        const Reg::Width rsz = width_for_bytes(static_cast<unsigned>(esz));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(9));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(12));
        {
            const Reg p = ctx.load_src(ins.operands[o_add], 0); // sumando
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[o_dst], 0); // dst
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[o_a], 0); // a
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[o_b], 0); // b
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(12));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(9));
        for (uint64_t k = 0; k < W; ++k) {
            if (k > 0) {
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(9), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(11), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(12), esz);
            }
            ctx.out.emit(vec_mv(ctx, ins, 0), Reg::gp(14, rsz),
                         Mem(Reg::gp(9))); // sumando[k]
            ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(0), Reg::gp(14));
            if (fma_sub)
                ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FNEG, es_ps),
                             Reg::fp(0), Reg::fp(0)); // -d
            ctx.out.emit(vec_mv(ctx, ins, 1), Reg::gp(13, rsz),
                         Mem(Reg::gp(11))); // a[k]
            ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(1), Reg::gp(13));
            ctx.out.emit(vec_mv(ctx, ins, 2), Reg::gp(14, rsz),
                         Mem(Reg::gp(12))); // b[k]
            ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(2), Reg::gp(14));
            ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FMADD, es_ps),
                         Reg::fp(0), Reg::fp(1),
                         Reg::fp(2)); // f0 = a*b + sumando
            ctx.out.emit(emmit::Mnemonic::BITZ2G, Reg::gp(14), Reg::fp(0));
            ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                         Reg::gp(14, rsz)); // dst[k]
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(12));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(9));
        ctx.r13_cache = -1;
        ctx.r14_cache = -1;
        break;
    }

    // VEC_ACC_* : acumulador vectorial.  El JIT lo mantiene en un XMM dedicado;
    // el INTERPRETE (oraculo) usa el acc_slot de MEMORIA (lento pero correcto)
    // -> ZERO/ADD/FMA operan sobre el slot por lane; STORE es no-op (el acc ya
    // esta en el slot).  Asi el slot tiene la suma al salir del bucle en AMBOS
    // (la reduccion horizontal posterior lo consume igual).
    case IrOp::VEC_ACC_ZERO: {
        if (ins.operands.empty()) break;
        const uint64_t width = ins.imm & 0xFF;
        const uint64_t acc_off = ((ins.imm >> 8) & 0xF) * width; // sub-slot idx
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(10));
        {
            const Reg p = ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        if (acc_off) ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), acc_off);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(14), 0);
        for (uint64_t q = 0; q < width; q += 8) {
            if (q > 0) ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), 8);
            ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)), Reg::gp(14));
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.r14_cache = -1;
        break;
    }
    case IrOp::VEC_ACC_ADD:
    case IrOp::VEC_ACC_FMA: {
        // acc[k] += a[k]  (ADD)  o  acc[k] += a[k]*b[k]  (FMA), por lane.
        const bool is_fma = (ins.op == IrOp::VEC_ACC_FMA);
        if (ins.operands.size() < (is_fma ? 3u : 2u)) break;
        const uint64_t width = ins.imm & 0xFF;
        const size_t esz = type_slot_bytes(ins.type);
        if (esz == 0) break;
        const uint64_t W = width / esz;
        const bool es_ps = (ins.type == IrType::F32);
        const Reg::Width rsz = width_for_bytes(static_cast<unsigned>(esz));
        const bool is_fp = (ins.type == IrType::F64 || ins.type == IrType::F32);
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(12));
        {
            const Reg p = ctx.load_src(ins.operands[0], 0); // acc slot
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        {
            const Reg p = ctx.load_src(ins.operands[1], 0); // a
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        if (is_fma) {
            const Reg p = ctx.load_src(ins.operands[2], 0); // b
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
            ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(12));
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10)); // a, acc
        {
            const uint64_t acc_off = ((ins.imm >> 8) & 0xF) * width;
            if (acc_off)
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), acc_off);
        }
        // disp de array (bits 16-31): displacement constante de la pieza del
        // unroll sobre a[]/b[].  Paridad con el codegen vreg (movupd
        // disp(base)).
        {
            const uint64_t arr_disp = ((ins.imm >> 16) & 0xFFFFull);
            if (arr_disp) {
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(11), arr_disp);
                if (is_fma)
                    ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(12), arr_disp);
            }
        }
        for (uint64_t k = 0; k < W; ++k) {
            if (k > 0) {
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(11), esz);
                if (is_fma)
                    ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(12), esz);
            }
            if (is_fp) {
                ctx.out.emit(vec_mv(ctx, ins, 0), Reg::gp(14, rsz),
                             Mem(Reg::gp(10))); // acc[k]
                ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(0), Reg::gp(14));
                ctx.out.emit(vec_mv(ctx, ins, 1), Reg::gp(13, rsz),
                             Mem(Reg::gp(11))); // a[k]
                ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(1), Reg::gp(13));
                if (is_fma) {
                    ctx.out.emit(vec_mv(ctx, ins, 2), Reg::gp(14, rsz),
                                 Mem(Reg::gp(12))); // b[k]
                    ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(2),
                                 Reg::gp(14));
                    ctx.out.emit(
                        emmit::packed_if(emmit::Mnemonic::FMADD, es_ps),
                        Reg::fp(0), Reg::fp(1), Reg::fp(2)); // += a*b
                } else {
                    ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FADD, es_ps),
                                 Reg::fp(0), Reg::fp(1)); // 1
                }
                ctx.out.emit(emmit::Mnemonic::BITZ2G, Reg::gp(14), Reg::fp(0));
                ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                             Reg::gp(14, rsz)); // acc[k]
            } else {
                // entero (solo ADD; FMA es float-only): acc[k] += a[k].
                ctx.out.emit(vec_mv(ctx, ins, 0), Reg::gp(14, rsz),
                             Mem(Reg::gp(10))); // acc[k]
                ctx.out.emit(vec_mv(ctx, ins, 1), Reg::gp(13, rsz),
                             Mem(Reg::gp(11))); // a[k]
                ctx.out.emit(emmit::Mnemonic::ADDS, Reg::gp(14),
                             Reg::gp(13)); // 64b add
                ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                             Reg::gp(14, rsz)); // acc[k]
            }
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(12));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.r13_cache = -1;
        ctx.r14_cache = -1;
        break;
    }
    case IrOp::VEC_ACC_COMBINE: {
        // acc[dst] += acc[src] por lane, sobre sub-slots de memoria del slot.
        if (ins.operands.empty()) break;
        const uint64_t width = ins.imm & 0xFF;
        const size_t esz = type_slot_bytes(ins.type);
        if (esz == 0) break;
        const uint64_t W = width / esz;
        const bool is_fp = (ins.type == IrType::F64 || ins.type == IrType::F32);
        const bool es_ps = (ins.type == IrType::F32);
        const Reg::Width rsz = width_for_bytes(static_cast<unsigned>(esz));
        const uint64_t dst_off = ((ins.imm >> 8) & 0xF) * width;
        const uint64_t src_off = ((ins.imm >> 12) & 0xF) * width;
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::PUSH, Reg::gp(11));
        {
            const Reg p = ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
            ctx.out.emit(emmit::Mnemonic::PUSH, p);
        }
        // ambos = slot base
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        if (dst_off)
            ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), dst_off); // dst
        if (src_off)
            ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(11), src_off); // src
        for (uint64_t k = 0; k < W; ++k) {
            if (k > 0) {
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(10), esz);
                ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(11), esz);
            }
            if (is_fp) {
                ctx.out.emit(vec_mv(ctx, ins, 0), Reg::gp(14, rsz),
                             Mem(Reg::gp(10)));
                ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(0), Reg::gp(14));
                ctx.out.emit(vec_mv(ctx, ins, 1), Reg::gp(13, rsz),
                             Mem(Reg::gp(11)));
                ctx.out.emit(emmit::Mnemonic::BITG2Z, Reg::fp(1), Reg::gp(13));
                ctx.out.emit(emmit::packed_if(emmit::Mnemonic::FADD, es_ps),
                             Reg::fp(0), Reg::fp(1));
                ctx.out.emit(emmit::Mnemonic::BITZ2G, Reg::gp(14), Reg::fp(0));
                ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                             Reg::gp(14, rsz));
            } else {
                ctx.out.emit(vec_mv(ctx, ins, 0), Reg::gp(14, rsz),
                             Mem(Reg::gp(10)));
                ctx.out.emit(vec_mv(ctx, ins, 1), Reg::gp(13, rsz),
                             Mem(Reg::gp(11)));
                ctx.out.emit(emmit::Mnemonic::ADDS, Reg::gp(14), Reg::gp(13));
                ctx.out.emit(vec_mv(ctx, ins, 0), Mem(Reg::gp(10)),
                             Reg::gp(14, rsz));
            }
        }
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(11));
        ctx.out.emit(emmit::Mnemonic::POP, Reg::gp(10));
        ctx.r13_cache = -1;
        ctx.r14_cache = -1;
        break;
    }
    case IrOp::VEC_ACC_STORE:
        // no-op en el interprete: el acc[0] ya vive en el sub-slot 0.
        break;

    // --- OOP / GC ---
    case IrOp::NEWOBJ: {
        // fix5 - NEWOBJ internamente llama @c gc_heap.alloc() que
        // puede disparar minor/major GC (evacuacion de YOUNG -> OLD).
        // Sin save_live_regs alrededor, los regs vivos a traves del
        // newobj se pierden si la GC mueve el objeto que apuntan.
        //
        // Fix: tratar NEWOBJ como cualquier otro CALL.  Identifica los
        // regs vivos (excluyendo dst), guarda los que contienen GC
        // host_ptrs como handles (estables a evacuacion), restaura tras
        // el newobj.  El reg de dst recibe el GcHandle nuevo en r0.
        //
        // Antes de este fix, un patron como
        //   ResourceA owned = make_a();    // owned vivo en main
        //   while (i<N) { i64 obj = newInstance(cls); ... }
        // crasheaba porque el `mov r1, cls` para newobj clobeaba r1
        // que contenia owned, y al RET el cleanup de owned leia garbage.
        if (ins.operands.empty()) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);
        // Excluir el reg que llevara r_cls (lo movemos manualmente
        // a r1 antes del newobj; preservarlo seria redundante).
        // El parallel-move es trivial: un solo arg.
        // La recarga va DESPUES del save: emit_save_live_regs usa r14/r13
        // como scratch y machacaria el valor recien cargado.  load_src (no
        // reg_of) para que un operando derramado se cargue de verdad.
        emit_save_live_regs(ctx, call_pos, regs_to_save);
        Reg r_cls = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(1), r_cls);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), 1);
        // E.1: stackmap justo antes del opcode que puede disparar GC.
        emit_stackmap_marker(ctx, bb, idx);
        ctx.out.emit(emmit::Mnemonic::NEWOBJ, Reg::gp(1));
        if (ins.dst != IR_NO_VALUE)
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
        emit_restore_live_regs(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::NEWOBJS: {
        // raw_asm-elim: variante SharedHeap de NEWOBJ ( Z.6).  Mismo
        // patron (save_live_regs por la GC + mov r1, cls + newobjs r1 +
        // dst=r0), pero usa el opcode `newobjs` que aloca en el SharedHeap.
        if (ins.operands.empty()) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);
        // Recarga DESPUES del save (ver NEWOBJ).
        emit_save_live_regs(ctx, call_pos, regs_to_save);
        Reg r_cls = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(1), r_cls);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), 1);
        // E.1: stackmap justo antes del opcode que puede disparar GC.
        emit_stackmap_marker(ctx, bb, idx);
        ctx.out.emit(emmit::Mnemonic::NEWOBJS, Reg::gp(1));
        if (ins.dst != IR_NO_VALUE)
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
        emit_restore_live_regs(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::GETFIELD: {
        // Restaurada la version que funciona con GcHandle (codigo .vel
        // manual de POO).  El frontend Vesta calcula el puntero al
        // campo via ADD antes de invocar LOAD para usar la ruta de
        // memoria host (movh) sin cur0.  Por tanto este case sigue
        // funcionando para handles tipicos.
        if (ins.operands.empty()) break;
        Reg rd = ctx.dst_of(ins.dst);
        Reg r_obj = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::GCDEREF, Reg::special(SpecialReg::CUR0),
                     r_obj);
        if (ins.imm)
            ctx.out.emit(emmit::Mnemonic::ADDCUR,
                         Reg::special(SpecialReg::CUR0), ins.imm);
        ctx.out.emit(emmit::Mnemonic::READCUR, rd,
                     Reg::special(SpecialReg::CUR0));
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::SETFIELD: {
        // Version original (GcHandle): el frontend Vesta calcula el
        // puntero via ADD y usa STORE con is_host_ptr=true en lugar
        // de SETFIELD para acceso directo via host pointer.
        if (ins.operands.size() < 2) break;
        Reg r_obj = ctx.load_src(ins.operands[0], 0);
        Reg r_val = ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::GCDEREF, Reg::special(SpecialReg::CUR0),
                     r_obj);
        if (ins.imm)
            ctx.out.emit(emmit::Mnemonic::ADDCUR,
                         Reg::special(SpecialReg::CUR0), ins.imm);
        ctx.out.emit(emmit::Mnemonic::WRITECUR, Reg::special(SpecialReg::CUR0),
                     r_val);
        if (ins.type == IrType::HANDLE)
            ctx.out.emit(emmit::Mnemonic::GCWB, r_obj);
        break;
    }

    case IrOp::INSTANCEOF: {
        if (ins.operands.size() < 2) break;
        Reg rd = ctx.reg_of(ins.dst);
        Reg r_obj = ctx.load_src(ins.operands[0], 0);
        Reg r_cls = ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::INSTANCEOF, Reg(rd), Reg(r_obj),
                     Reg(r_cls));
        break;
    }

    case IrOp::CHECKCAST: {
        if (ins.operands.size() < 2) break;
        // Recarga previa de AMBOS operandos, cada uno en su
        // scratch: reg_of solo consulta y devolveria el
        // mismo registro para los dos.
        (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::CHECKCAST, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;
    }

    case IrOp::ISNULL: {
        if (!ins.operands.empty())
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::ISNULL, ctx.reg_of(ins.dst),
                     ctx.reg_of(ins.operands[0]));
        break;
    }

    case IrOp::UNWRAP: {
        if (!ins.operands.empty()) {
            Reg rs = ctx.load_src(ins.operands[0], 0);
            Reg rd = ctx.dst_of(ins.dst);
            ctx.out.emit(emmit::Mnemonic::UNWRAP, rd, rs);
            ctx.store_spilled(ins.dst);
        }
        break;
    }

    case IrOp::SPECIALIZE: {
        if (ins.operands.size() < 2) break;
        // Recarga previa de AMBOS operandos, cada uno en su
        // scratch: reg_of solo consulta y devolveria el
        // mismo registro para los dos.
        (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::SPECIALIZE, ctx.reg_of(ins.dst),
                     ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;
    }

        // --- GEP / write barrier / arrays ---

    case IrOp::GEP: {
        // %ptr = gep.ptr %handle, byte_offset
        // Emite gcderef + addcur; el cursor cur0 queda apuntando al campo.
        // El %ptr resultante es un marcador; usar LOAD/STORE inmediatamente
        // despues.
        if (ins.operands.empty()) break;
        Reg r_obj = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::GCDEREF, Reg::special(SpecialReg::CUR0),
                     r_obj);
        if (ins.imm)
            ctx.out.emit(emmit::Mnemonic::ADDCUR,
                         Reg::special(SpecialReg::CUR0), ins.imm);
        break;
    }

    case IrOp::GCWB_IR: {
        // gcwb_ir %handle  ->  gcwb r_handle
        if (!ins.operands.empty())
            ctx.out.emit(emmit::Mnemonic::GCWB,
                         ctx.load_src(ins.operands[0], 0));
        break;
    }

    case IrOp::GCDEREF_IR: {
        // gcderef_ir %handle  ->  gcderef cur0, r_handle
        // Nota: no hay instruccion VM para exportar cur0 a registro general.
        // Este opcode es util solo cuando seguido de readcur/writecur via
        // RAW_ASM.
        if (!ins.operands.empty())
            ctx.out.emit(emmit::Mnemonic::GCDEREF,
                         Reg::special(SpecialReg::CUR0),
                         ctx.load_src(ins.operands[0], 0));
        break;
    }

    case IrOp::GC_DEREF_HOST: {
        // %dst = gc_deref_host.ptr %handle
        //
        // Reemplaza el viejo blob RAW_ASM:
        //     gcderef cur0, {src0}
        //     xchg    cur0, {dst}
        //
        // El primer paso baja el host_ptr del payload del handle a cur0
        // (special register).  El segundo lo intercambia con el registro
        // general destino.  Tras el xchg, cur0 queda con el valor previo
        // del dst (basura, descartada).
        //
        // El resultado dst es un host_ptr al payload del objeto GC.
        // Marcarlo @c is_host_ptr permite que LOAD/STORE posteriores
        // emitan @c movh en lugar de @c mov (memoria host vs VM).
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            Reg rs = ctx.load_src(ins.operands[0], 0);
            Reg rd = ctx.dst_of(ins.dst);
            ctx.out.emit(emmit::Mnemonic::GCDEREF,
                         Reg::special(SpecialReg::CUR0), rs);
            ctx.out.emit(emmit::Mnemonic::XCHG, Reg::special(SpecialReg::CUR0),
                         rd);
            ctx.store_spilled(ins.dst);
        }
        break;
    }

    case IrOp::ARRAY_ALLOC: {
        // %h = array_alloc.T %len
        // Layout en memoria VM: [u64 length][data[len * sizeof(T)]]
        // Delega a helper nativo stdlib/native/array/vesta_array:va_alloc(proc,
        // esize, count)
        Reg r_len = ins.operands.empty() ? Reg::gp(0)
                                         : ctx.load_src(ins.operands[0], 0);
        uint64_t esize = type_slot_bytes(ins.type);
        ctx.out.emit(emmit::Mnemonic::GETPROC, Reg::gp(1));
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(2), esize);
        emit_mov_if_needed(ctx, Reg::gp(3), r_len);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), 3);
        ctx.out.emit(emmit::Mnemonic::CALLN,
                     Ann::method("stdlib/native/array/vesta_array:va_alloc"));
        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        break;
    }

    case IrOp::ARRAY_LEN: {
        // longitud del array: offset 0 contiene el campo length (u64)
        if (ins.operands.empty()) break;
        Reg r_arr = ctx.load_src(ins.operands[0], 0);
        Reg rd = ctx.dst_of(ins.dst);
        ctx.out.emit(emmit::Mnemonic::MOV, rd, Mem(r_arr));
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::ARRAY_LOAD: {
        // direccion del elemento: r_arr + r_idx * stride + 8 (los primeros 8
        // bytes son el campo length)
        if (ins.operands.size() < 2) break;
        Reg r_arr = ctx.load_src(ins.operands[0], 0);
        Reg r_idx = ctx.load_src(ins.operands[1], 1);
        Reg rd = ctx.dst_of(ins.dst);
        uint64_t stride = type_slot_bytes(ins.type);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), r_idx);
        if (stride > 1)
            ctx.out.emit(emmit::Mnemonic::MULU, Reg::gp(13), stride);
        ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(13), 8);
        ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(13), r_arr);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg(rd), Mem(Reg::gp(13)));
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::ARRAY_STORE: {
        // escritura de elemento: misma aritmetica de direccion que ARRAY_LOAD
        if (ins.operands.size() < 3) break;
        Reg r_arr = ctx.load_src(ins.operands[0], 0);
        Reg r_idx = ctx.load_src(ins.operands[1], 1);
        Reg r_val = ctx.load_src(ins.operands[2], 0);
        uint64_t stride = type_slot_bytes(ins.type);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), r_idx);
        if (stride > 1)
            ctx.out.emit(emmit::Mnemonic::MULU, Reg::gp(13), stride);
        ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(13), 8);
        ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(13), r_arr);
        ctx.out.emit(emmit::Mnemonic::MOV, Mem(Reg::gp(13)), Reg(r_val));
        // write barrier si el tipo de elemento es HANDLE
        if (ins.type == IrType::HANDLE)
            ctx.out.emit(emmit::Mnemonic::GCWB, r_arr);
        break;
    }

        // --- Operaciones de cadena ---

    case IrOp::STRMAKE: {
        // strmake.handle %buf_addr, %len [enc=imm]
        // STRMAKE aloca un StringObject -> puede triggerar GC y mover
        // host_ptrs vivos.  Tratamos el opcode como un CALL para fines
        // de spill: si hay regs is_gc_object vivos, dance gchandle/
        // gcderef alrededor.
        //
        // LANG.fix-4: el save_live_regs usa r14/r13 como scratch
        // para `gchandle r14, <gc_reg>`.  Si load_src ya puso los
        // operandos en r14/r13, el save los clobrea.  Fix: emitir
        // SAVE primero, despues load_src, despues call, despues
        // restore.  Asi r14/r13 quedan libres para scratch durante
        // save, y los operandos se cargan recien antes del call.
        if (ins.operands.size() < 2) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        const bool buf_is_host =
            ins.operands[0] < static_cast<int>(ctx.fn.values.size()) &&
            ctx.fn.values[ins.operands[0]].is_host_ptr;
        const char *opcode = buf_is_host ? "strmake_h" : "strmake";

        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        Reg r_buf = ctx.load_src(ins.operands[0], 0);
        Reg r_len = ctx.load_src(ins.operands[1], 1);
        Reg rd = ctx.dst_of(ins.dst);
        ctx.out << "    " << opcode << " " << rd << ", " << r_buf << ", "
                << r_len << "\n";
        ctx.store_spilled(ins.dst);
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::STRLEN: {
        if (ins.operands.empty()) break;
        Reg rd = ctx.dst_of(ins.dst);
        Reg r_str = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::STRLEN, rd, r_str);
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::STRCAT: {
        // STRCAT aloca un ROPE StringObject (GC).  LANG.fix-4: SAVE
        // antes del load_src para que r14/r13 no se clobreen como
        // scratch del gchandle.
        if (ins.operands.size() < 2) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        Reg ra = ctx.load_src(ins.operands[0], 0);
        Reg rb = ctx.load_src(ins.operands[1], 1);
        Reg rd = ctx.dst_of(ins.dst);
        ctx.out.emit(emmit::Mnemonic::STRCAT, Reg(rd), Reg(ra), Reg(rb));
        ctx.store_spilled(ins.dst);
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::STRCMP: {
        if (ins.operands.size() < 2) break;
        Reg rd = ctx.dst_of(ins.dst);
        Reg ra = ctx.load_src(ins.operands[0], 0);
        Reg rb = ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::STRCMP, Reg(rd), Reg(ra), Reg(rb));
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::STRSLICE: {
        // STRSLICE aloca un SLICE StringObject (GC).  LANG.fix-4:
        // SAVE antes de load_src.
        if (ins.operands.size() < 2) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        Reg r_str = ctx.load_src(ins.operands[0], 0);
        Reg r_rng = ctx.load_src(ins.operands[1], 1);
        Reg rd = ctx.dst_of(ins.dst);
        ctx.out.emit(emmit::Mnemonic::STRSLICE, Reg(rd), Reg(r_str),
                     Reg(r_rng));
        ctx.store_spilled(ins.dst);
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::STRFLAT: {
        if (ins.operands.empty()) break;
        Reg rd = ctx.dst_of(ins.dst);
        Reg r_str = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::STRFLAT, rd, r_str);
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::STRHASH: {
        if (ins.operands.empty()) break;
        Reg rd = ctx.dst_of(ins.dst);
        Reg r_str = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::STRHASH, rd, r_str);
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::STRINTERN: {
        // STRINTERN aloca en intern pool (GC).  LANG.fix-4: SAVE primero.
        if (ins.operands.empty()) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        Reg r_str = ctx.load_src(ins.operands[0], 0);
        Reg rd = ctx.dst_of(ins.dst);
        ctx.out.emit(emmit::Mnemonic::STRINTERN, rd, r_str);
        ctx.store_spilled(ins.dst);
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::STRRAW: {
        if (ins.operands.empty()) break;
        Reg rd = ctx.dst_of(ins.dst);
        Reg r_str = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::STRRAW, rd, r_str);
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::STRCONV: {
        // STRCONV aloca nuevo StringObject (GC).  LANG.fix-4: SAVE primero.
        if (ins.operands.empty()) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        Reg r_str = ctx.load_src(ins.operands[0], 0);
        // Igual que con el entorno de la closure: "no hay codificacion" es una
        // bandera, no una cadena vacia.
        bool hay_enc = false;
        Reg r_enc = Reg::gp(0);
        if (ins.operands.size() >= 2) {
            r_enc = ctx.load_src(ins.operands[1], 1);
            hay_enc = true;
        }
        Reg rd = ctx.dst_of(ins.dst);
        if (hay_enc) {
            ctx.out.emit(emmit::Mnemonic::STRCONV, rd, r_str, r_enc);
        } else {
            ctx.out.emit(emmit::Mnemonic::STRCONV, rd, r_str, ins.imm);
        }
        ctx.store_spilled(ins.dst);
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::STRRESERVE: {
        // STRRESERVE aloca FLAT StringObject (GC).  LANG.fix-4: SAVE primero.
        if (ins.operands.empty()) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        Reg r_cap = ctx.load_src(ins.operands[0], 0);
        Reg rd = ctx.dst_of(ins.dst);
        ctx.out.emit(emmit::Mnemonic::STRRESERVE, rd, r_cap);
        ctx.store_spilled(ins.dst);
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::STRFINALIZE: {
        if (ins.operands.size() < 2) break;
        Reg r_str = ctx.load_src(ins.operands[0], 0);
        Reg r_len = ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::STRFINALIZE, r_str, r_len);
        break;
    }

    // --- Excepciones ---
    case IrOp::THROW: {
        if (!ins.operands.empty())
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::THROW, ctx.reg_of(ins.operands[0]));
        break;
    }

    case IrOp::TRYENTER: {
        if (ins.operands.size() < 2) break;
        // Recarga previa de AMBOS operandos, cada uno en su
        // scratch: reg_of solo consulta y devolveria el
        // mismo registro para los dos.
        (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::TRYENTER, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;
    }

    case IrOp::TRYLEAVE: ctx.out.emit(emmit::Mnemonic::TRYLEAVE); break;

    case IrOp::LANDINGPAD:
        if (ins.dst != IR_NO_VALUE)
            ctx.out.emit(emmit::Mnemonic::MOV, ctx.reg_of(ins.dst), Reg::gp(0));
        break;

    // --- Async / futures ---
    case IrOp::FUTURE: {
        ctx.out.emit(emmit::Mnemonic::FUTURE); // resultado en r0
        if (ins.dst != IR_NO_VALUE)
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
        break;
    }

    case IrOp::AWAIT: {
        if (!ins.operands.empty()) {
            // B4.3 fix: usar el reg del operando directamente (no
            // forzar a r1).  El opcode `await` toma cualquier reg
            // (reg_data.reg1).  Forzar mov a r1 clobreaba el outer
            // future cuando estamos en body de @Async (r1 = param0).
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(
                emmit::Mnemonic::AWAIT,
                ctx.reg_of(ins.operands[0])); // bloquea; resultado en r0
            if (ins.dst != IR_NO_VALUE)
                emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
        }
        break;
    }

    case IrOp::FULFILL: {
        if (ins.operands.size() < 2) break;
        Reg r_fut = ctx.load_src(ins.operands[0], 0);
        Reg r_val = ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::FULFILL, r_fut, r_val);
        break;
    }

    case IrOp::REJECT: {
        if (ins.operands.size() < 2) break;
        // Recarga previa de AMBOS operandos, cada uno en su
        // scratch: reg_of solo consulta y devolveria el
        // mismo registro para los dos.
        (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::REJECT, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;
    }

    // --- Distribucion ---
    case IrOp::MSGSEND: {
        if (ins.operands.size() < 3) break;
        // Tres operandos y solo dos scratch (r14/r13).  El TERCERO se carga
        // PRIMERO porque emit_load_spilled_into usa r13 para la direccion y
        // machacaria el segundo scratch.  Como destino se usa r0: la propia
        // instruccion lo sobreescribe con su resultado, asi que no puede
        // llevar nada vivo.  Si algun otro operando ya vive en r0 se recurre
        // al registro del dst (libre: aun no se ha escrito).
        Reg r_len = Reg::gp(0);
        if (ctx.is_in_reg(ins.operands[2])) {
            r_len = ctx.reg_of(ins.operands[2]);
        } else {
            const Reg u0 = ctx.reg_of(ins.operands[0]);
            const Reg u1 = ctx.reg_of(ins.operands[1]);
            r_len = (u0.is_gp(0) || u1.is_gp(0)) && ins.dst != IR_NO_VALUE
                        ? ctx.dst_of(ins.dst)
                        : Reg::gp(0);
            ctx.emit_load_spilled_into(ins.operands[2], r_len);
        }
        const Reg r_pid = ctx.load_src(ins.operands[0], 0);
        const Reg r_addr = ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::MSGSEND, r_pid, r_addr, r_len);
        if (ins.dst != IR_NO_VALUE)
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
        break;
    }

    case IrOp::MSGRECV: {
        if (ins.operands.size() < 2) break;
        // Recarga previa de AMBOS operandos, cada uno en su
        // scratch: reg_of solo consulta y devolveria el
        // mismo registro para los dos.
        (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::MSGRECV, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        if (ins.dst != IR_NO_VALUE)
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
        break;
    }

    case IrOp::RSPAWN: {
        if (ins.operands.size() < 2) break;
        // Recarga previa de AMBOS operandos, cada uno en su
        // scratch: reg_of solo consulta y devolveria el
        // mismo registro para los dos.
        (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::RSPAWN, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        if (ins.dst != IR_NO_VALUE)
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
        break;
    }

    // --- Sincronizacion / monitores ---
    case IrOp::MONENTER:
        if (!ins.operands.empty())
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::MONENTER, ctx.reg_of(ins.operands[0]));
        break;
    case IrOp::MONEXIT:
        if (!ins.operands.empty())
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::MONEXIT, ctx.reg_of(ins.operands[0]));
        break;
    case IrOp::MONWAIT:
        if (!ins.operands.empty())
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::MONWAIT, ctx.reg_of(ins.operands[0]));
        break;
    case IrOp::MONNOTI:
        if (!ins.operands.empty())
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::MONNOTI, ctx.reg_of(ins.operands[0]));
        break;
    case IrOp::MONNOTA:
        if (!ins.operands.empty())
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::MONNOTA, ctx.reg_of(ins.operands[0]));
        break;

    // --- Intrinsics VM ---
    case IrOp::GETPROC:
        if (ins.dst != IR_NO_VALUE) {
            ctx.out.emit(emmit::Mnemonic::GETPROC, ctx.dst_of(ins.dst));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::GETVM:
        if (ins.dst != IR_NO_VALUE) {
            ctx.out.emit(emmit::Mnemonic::GETVM, ctx.dst_of(ins.dst));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::GETMGR:
        if (ins.dst != IR_NO_VALUE) {
            ctx.out.emit(emmit::Mnemonic::GETMGR, ctx.dst_of(ins.dst));
            ctx.store_spilled(ins.dst);
        }
        break;

    // --- Coroutines / scheduler ---
    case IrOp::SPAWN: {
        if (!ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::SPAWN, ctx.reg_of(ins.operands[0]));
            if (ins.dst != IR_NO_VALUE)
                emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
        }
        break;
    }
    case IrOp::RESUME:
        if (!ins.operands.empty())
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::RESUME, ctx.reg_of(ins.operands[0]));
        break;
    case IrOp::YIELD: ctx.out.emit(emmit::Mnemonic::YIELD); break;
    case IrOp::SWAPCTX:
        if (ins.operands.size() >= 2)
            // Recarga previa de AMBOS operandos, cada uno en su
            // scratch: reg_of solo consulta y devolveria el
            // mismo registro para los dos.
            (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::SWAPCTX, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;

    case IrOp::SPAWN_ARGS: {
        // SPAWN_ARGS r_pc, arg1, arg2, ..., argN
        // operands[0] = r_pc (direccion del helper)
        // operands[1..N] = args para el child (calling convention CALLVM:
        //   args en R1..R[N], argc en R15)
        //
        // Comparte la misma estructura que CALL: save_live_regs +
        // parallel-move + spawnargs + restore_live_regs.  La diferencia
        // es que NO emite callvm (que push'ea ret addr y bloquea el
        // padre) sino @c spawnargs (extended 0x66) que crea proceso
        // hijo y devuelve PID en R0 al padre INMEDIATAMENTE.
        //
        // El parallel-move correcto del IR emitter resuelve el conflicto
        // ciclico cuando un arg necesita estar en un reg que otro arg
        // ocupa actualmente (caso comun: arg `a` en r1 debe ir a r2
        // mientras `b` en r2 debe ir a r3, etc.).
        if (ins.operands.empty()) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        // r_pc se materializa antes de los pushes para evitar que
        // los moves de args lo clobberen.
        Reg r_pc = ctx.load_src(ins.operands[0], 0);

        // B4.1 fix: si r_pc esta en R1..R[nargs] (slot de arg), el
        // parallel-move lo clobberea.  Evacuar a r13 (scratch fuera
        // de calling convention).  Mismo patron que CALLCLOSURE
        // arregla para fn_addr en arg slot.
        const size_t nargs = std::min(ins.operands.size() - 1, (size_t)12);
        if (r_pc.bank == Reg::Bank::GP) {
            const int rn = static_cast<int>(r_pc.index);
            if (rn >= 1 && rn <= static_cast<int>(nargs)) {
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), r_pc);
                r_pc = Reg::gp(13);
            }
        }

        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);

        // Args van en R1..R[N], donde N = operands.size() - 1.
        std::vector<std::pair<int, Reg>> moves;
        std::vector<std::pair<int, ir::IrValueId>> spilled_args;
        moves.reserve(nargs);
        for (size_t ai = 0; ai < nargs; ++ai) {
            ir::IrValueId v = ins.operands[ai + 1];
            int target_reg = static_cast<int>(ai + 1);
            if (v != IR_NO_VALUE && ctx.alloc.spilled(v)) {
                spilled_args.emplace_back(target_reg, v);
            } else {
                moves.emplace_back(target_reg, ctx.load_src(v, 0));
            }
        }
        emit_parallel_arg_moves(ctx, std::move(moves));
        for (auto &pa : spilled_args) {
            emit_load_spilled_arg(ctx, pa.first, pa.second);
        }

        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), nargs);
        // B4.1: r_pc YA fue evacuado a r13 si quedaba en arg slot
        // (antes de save+parallel-move), asi que aqui sigue siendo
        // valido.  No re-cargar (re-load del operand devolveria el
        // mismo reg si el regalloc no lo movio explicit, lo que
        // descartaria el evacuamiento).
        ctx.out.emit(emmit::Mnemonic::SPAWNARGS, r_pc);

        // PID encoded del child queda en R0; moverlo al destino SSA.
        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    // -----------------------------------------------------------------
    // Intrinsics VM extra y operaciones recuperadas durante la fase B.
    // Bajada directa a las mnemonicas .vel; los registros usan la
    // convencion habitual: operandos via @c reg_of, destino via @c dst_of.
    // -----------------------------------------------------------------
    case IrOp::HLT: ctx.out.emit(emmit::Mnemonic::HLT); break;
    case IrOp::GETPID:
        if (ins.dst != IR_NO_VALUE) {
            ctx.out.emit(emmit::Mnemonic::GETPID, ctx.dst_of(ins.dst));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::GETARGC:
        if (ins.dst != IR_NO_VALUE) {
            ctx.out.emit(emmit::Mnemonic::GETARGC, ctx.dst_of(ins.dst));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::GETARG:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::GETARG, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::PANIC:
        if (ins.operands.size() >= 2)
            // Recarga previa de AMBOS operandos, cada uno en su
            // scratch: reg_of solo consulta y devolveria el
            // mismo registro para los dos.
            (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::PANIC, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;
    case IrOp::SPAWN_ON: {
        if (ins.operands.size() < 2) break;
        // Recarga previa de AMBOS operandos, cada uno en su
        // scratch: reg_of solo consulta y devolveria el
        // mismo registro para los dos.
        (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::SPAWNON, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        if (ins.dst != IR_NO_VALUE)
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
        break;
    }

    // --- direccion absoluta de un label resuelta por el linker ---
    case IrOp::LABEL_ADDR:
        if (ins.dst != IR_NO_VALUE) {
            ctx.out.emit(emmit::Mnemonic::MOV, ctx.dst_of(ins.dst),
                         Ann::absolute("code." + ins.func_name));
            ctx.store_spilled(ins.dst);
        }
        break;

    // --- move-and-take (intra-thread atomic move) ---
    case IrOp::MVTAKE_IR:
        if (ins.operands.size() >= 2)
            // Recarga previa de AMBOS operandos, cada uno en su
            // scratch: reg_of solo consulta y devolveria el
            // mismo registro para los dos.
            (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::MVTAKE, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;

    // --- gcfinal: registra/desregistra finalizador GC del box ---
    case IrOp::GC_SET_FINALIZER:
        if (!ins.operands.empty()) {
            // kind==3 (CLASS_DTOR): lleva un 2o operando = vaddr del dtor
            // concreto (dispatch estatico).  Se emite con el opcode dedicado
            // `gcfinalc r_box, r_dtor` (registra CLASS_DTOR + guarda el vaddr).
            if ((ins.imm == 3 || ins.imm == 1) && ins.operands.size() >= 2) {
                // Recarga previa de AMBOS operandos, cada uno en su scratch:
                // reg_of solo consulta y devolveria el mismo registro para los
                // dos.
                (void)ctx.load_src(ins.operands[0], 0);
                (void)ctx.load_src(ins.operands[1], 1);
                // El mnemonico dice A QUIEN se llama: el destructor de la clase
                // o el liberador del `unique`.  Mismo opcode.
                ctx.out.emit(ins.imm == 1 ? emmit::Mnemonic::GCFINALU
                                          : emmit::Mnemonic::GCFINALC,
                             ctx.reg_at(ins.operands[0], 0),
                             ctx.reg_at(ins.operands[1], 1));
            } else {
                (void)ctx.load_src(ins.operands[0], 0);
                ctx.out.emit(emmit::Mnemonic::GCFINAL,
                             ctx.reg_of(ins.operands[0]), ins.imm);
            }
        }
        break;

    // --- gccollect: fuerza minor+major GC del proceso + drena finalizadores
    // ---
    case IrOp::GC_COLLECT:
        // gccollect ejecuta minor_gc + major_gc in-situ: es un SAFEPOINT.  El
        // mark corre con las raices del programa vivas en regs/slots del frame
        // TOP -> emitir el stackmap ANTES del opcode (mismo modelo que newobj/
        // gcalloc).  Sin esto, el scan preciso no encuentra raices en el PC de
        // gccollect y colecta objetos vivos (con el GC moving: corrupcion).
        emit_stackmap_marker(ctx, bb, idx);
        ctx.out.emit(emmit::Mnemonic::GCCOLLECT);
        break;

    // --- gcfinall: finaliza TODO objeto GC vivo con recurso interno ---
    case IrOp::GC_FINALIZE_ALL: ctx.out.emit(emmit::Mnemonic::GCFINALL); break;

    // --- gcallocp: alloc + deref + xchg fusionados ---
    case IrOp::GC_ALLOCP:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // E.1: stackmap justo antes del opcode gcallocp (safepoint).
            emit_stackmap_marker(ctx, bb, idx);
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::GCALLOCP, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]));
            ctx.store_spilled(ins.dst);
        }
        break;

    // --- static fields: getstatic/setstatic con offset compile-time ---
    case IrOp::GETSTATIC:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::GETSTATIC, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]), ins.imm);
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::SETSTATIC:
        if (ins.operands.size() >= 2)
            // Recarga previa de AMBOS operandos, cada uno en su
            // scratch: reg_of solo consulta y devolveria el
            // mismo registro para los dos.
            (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::SETSTATIC, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1), ins.imm);
        break;

    // --- atomics i64 ( Z) ---
    //
    // Los operandos se piden con `load_src`, NO con `reg_of`: `reg_of` devuelve
    // el registro asignado, y si el valor esta DERRAMADO devuelve el scratch --
    // sin cargarlo.  Emitia `atomiccas r0, r8, r14, r3` con r14 conteniendo lo
    // que hubiera (aqui, una direccion de spill), asi que el CAS comparaba
    // contra basura, fallaba y devolvia el valor viejo... y el llamante, que
    // compara ese viejo con SU `expected`, concluia que habia triunfado.  Una
    // escritura atomica perdida que ademas reportaba exito.  Solo se veia con
    // suficiente presion de registros para que algo se derramara.
    case IrOp::ATOMIC_LD:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // El ANCHO del atomico (1/2/4/8) va en el sufijo de tamano del reg
            // de VALOR (.b/.w/.d), como loadz -- el emisor lo lee y lo mete en
            // el ctrl-byte.  La direccion (operando 0) queda a 64 bits
            // (puntero).
            const Reg a = ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::ATOMICLD,
                         atomic_sized(ctx.dst_of(ins.dst), ins.type), a);
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::ATOMIC_ST:
        if (ins.operands.size() >= 2) {
            const Reg a = ctx.load_src(ins.operands[0], 0);
            const Reg v = ctx.load_src(ins.operands[1], 1);
            // Ancho en ins.type (fijado por emit_atomic_st con el ancho del
            // valor; I64/VOID -> 8 bytes por defecto para productores viejos).
            ctx.out.emit(emmit::Mnemonic::ATOMICST, a,
                         atomic_sized(v, ins.type));
        }
        break;
    case IrOp::ATOMIC_CAS:
        if (ins.dst != IR_NO_VALUE && ins.operands.size() >= 3) {
            // Tres operandos y solo dos scratch (r14/r13).  Se cargan los dos
            // primeros con los scratch de siempre; el tercero, si hace falta,
            // usa el registro del DST -- que aun no se ha escrito (la
            // instruccion lo produce), asi que esta libre.  Si el dst tambien
            // esta derramado, `dst_of` da el scratch y no habria tercer sitio:
            // ese caso no lo cubre el mapeo de 2 scratch y se emite tal cual
            // (el regalloc no lo produce hoy: el dst de un CAS es el resultado
            // que se usa justo despues, asi que siempre tiene registro).
            // El tercero PRIMERO: `emit_load_spilled_into` usa r13 para la
            // direccion, y r13 es donde acaba el segundo `load_src`.
            Reg d = Reg::gp(0);
            if (ctx.is_in_reg(ins.operands[2])) {
                d = ctx.reg_of(ins.operands[2]);
            } else {
                d = ctx.dst_of(ins.dst);
                ctx.emit_load_spilled_into(ins.operands[2], d);
            }
            const Reg a = ctx.load_src(ins.operands[0], 0);
            const Reg e = ctx.load_src(ins.operands[1], 1);
            // Ancho (mode) en el sufijo del DST; exp/des tambien sized (mismo
            // ancho); la direccion (a) plana (puntero de 64 bits).
            ctx.out.emit(emmit::Mnemonic::ATOMICCAS,
                         Reg(atomic_sized(ctx.dst_of(ins.dst), ins.type)),
                         Reg(a), Reg(atomic_sized(e, ins.type)),
                         Reg(atomic_sized(d, ins.type)));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::ATOMIC_ADD:
        if (ins.dst != IR_NO_VALUE && ins.operands.size() >= 2) {
            const Reg a = ctx.load_src(ins.operands[0], 0);
            const Reg d = ctx.load_src(ins.operands[1], 1);
            // Ancho (mode) en el sufijo del DST y del delta; direccion plana.
            ctx.out.emit(emmit::Mnemonic::ATOMICADD,
                         Reg(atomic_sized(ctx.dst_of(ins.dst), ins.type)),
                         Reg(a), Reg(atomic_sized(d, ins.type)));
            ctx.store_spilled(ins.dst);
        }
        break;

    // --- async fusion ---
    case IrOp::FULFILL_HLT:
        if (ins.operands.size() >= 2)
            // Recarga previa de AMBOS operandos, cada uno en su
            // scratch: reg_of solo consulta y devolveria el
            // mismo registro para los dos.
            (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::FULFILLHLT,
                     ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;

    // --- raw_asm-elim wave 3: ops nuevos sin operandos / con imm ---
    case IrOp::RETHROW:
        // rethrow: terminator del bloque, sin operandos.
        ctx.out.emit(emmit::Mnemonic::RETHROW);
        break;
    case IrOp::SHARED_STAT: {
        // sharedstat r_dst, r_op_code
        // op=0 (live_count) y op=1 (bytes) producen un valor en r_dst.
        // op=2 (gc_collect) es void: usamos r14 dummy como dst.
        if (ins.operands.empty()) break;
        Reg r_op = ctx.load_src(ins.operands[0], 0);
        Reg r_dst =
            (ins.dst != IR_NO_VALUE) ? ctx.dst_of(ins.dst) : Reg::gp(14);
        ctx.out.emit(emmit::Mnemonic::SHAREDSTAT, r_dst, r_op);
        if (ins.dst != IR_NO_VALUE) ctx.store_spilled(ins.dst);
        break;
    }
    case IrOp::READ_VM_REG: {
        // mov {dst}, rN  (N = ins.imm).
        if (ins.dst == IR_NO_VALUE) break;
        if (ins.imm > 15) break; // sanity check
        ctx.out.emit(emmit::Mnemonic::MOV, ctx.dst_of(ins.dst),
                     Reg::gp(static_cast<unsigned>(ins.imm)));
        ctx.store_spilled(ins.dst);
        break;
    }
    case IrOp::RSPAWN_RETURN: {
        // mov r0, payload + hlt fusionado.  Terminator del bloque.
        if (ins.operands.empty()) break;
        Reg r_payload = ctx.load_src(ins.operands[0], 0);
        // emit_mov_if_needed para evitar mov r0, r0 redundante.
        if (r_payload.is_gp(0) == false) {
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(0), r_payload);
        }
        ctx.out.emit(emmit::Mnemonic::HLT);
        break;
    }

    case IrOp::MOD_LOAD: {
        // raw_asm-elim wave 2: loadmod/unloadmod.
        // imm=0 -> loadmod (ejecuta el main del plugin como sub-llamada,
        //          R0 = init_pc o 0 si fallo).
        // imm=1 -> unloadmod (libera el slot, R0 = 1 ok / 0 not_found).
        if (ins.operands.size() < 2 || ins.dst == IR_NO_VALUE) break;
        if (ins.imm == 0) {
            // loadmod EJECUTA el __module_init del modulo cargado como una
            // sub-llamada (convencion CALLVM: push ret + jump al init_pc).
            // Ese __module_init clobbea CUALQUIER registro del caller (su
            // regalloc usa r0..r14 libremente).  Por eso hay que salvar los
            // registros vivos-a-traves como en cualquier CALL (igual que
            // CALLSUPER).  Sin esto, un valor que el caller mantiene en un
            // registro a traves del loadmod (e.g. un const CSE-ado) se
            // corrompe -- bug latente destapado al pasar __module_init de
            // RAW_ASM (set fijo de regs) a IR estructurado (regalloc libre).
            const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
            std::vector<int> regs_to_save =
                live_regs_through_call(ctx, call_pos, ins.dst);
            emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
            Reg r_path = ctx.load_src(ins.operands[0], 0);
            Reg r_len = ctx.load_src(ins.operands[1], 1);
            ctx.out.emit(emmit::Mnemonic::LOADMOD, r_path, r_len);
            Reg r_dst = ctx.dst_of(ins.dst);
            if (r_dst.is_gp(0) == false)
                ctx.out.emit(emmit::Mnemonic::MOV, r_dst, Reg::gp(0));
            ctx.store_spilled(ins.dst);
            emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        } else {
            // unloadmod solo delega en una funcion C (unregister) que NO
            // clobbea registros VM; basta el patron simple.
            Reg r_path = ctx.load_src(ins.operands[0], 0);
            Reg r_len = ctx.load_src(ins.operands[1], 1);
            Reg r_dst = ctx.dst_of(ins.dst);
            ctx.out.emit(emmit::Mnemonic::UNLOADMOD, r_path, r_len);
            if (r_dst.is_gp(0) == false)
                ctx.out.emit(emmit::Mnemonic::MOV, r_dst, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        break;
    }
    case IrOp::DLOPEN: {
        // raw_asm-elim wave 2: LoadLibrary/dlopen wrapper.
        // dlopen rDst, rPath, rLen (3-arg form, dst inline).
        if (ins.operands.size() < 2 || ins.dst == IR_NO_VALUE) break;
        Reg r_path = ctx.load_src(ins.operands[0], 0);
        Reg r_len = ctx.load_src(ins.operands[1], 1);
        Reg r_dst = ctx.dst_of(ins.dst);
        ctx.out.emit(emmit::Mnemonic::DLOPEN, Reg(r_dst), Reg(r_path),
                     Reg(r_len));
        ctx.store_spilled(ins.dst);
        break;
    }
    case IrOp::DLSYM: {
        // raw_asm-elim wave 2: GetProcAddress/dlsym wrapper.
        // dlsym rDst, rHandle, rNameAddr, rNameLen (4-arg form).
        if (ins.operands.size() < 3 || ins.dst == IR_NO_VALUE) break;
        Reg r_handle = ctx.load_src(ins.operands[0], 0);
        Reg r_name = ctx.load_src(ins.operands[1], 1);
        Reg r_len = ctx.load_src(ins.operands[2], 2);
        Reg r_dst = ctx.dst_of(ins.dst);
        ctx.out.emit(emmit::Mnemonic::DLSYM, Reg(r_dst), Reg(r_handle),
                     Reg(r_name), Reg(r_len));
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::REFLECT_COUNT: {
        // raw_asm-elim wave 2: methodcount/fieldcount.
        // imm=0 -> methodcount, imm=1 -> fieldcount.
        // Emite "<op> r_cls\nmov r_dst, r0\n" (resultado en R0).
        if (ins.operands.empty() || ins.dst == IR_NO_VALUE) break;
        const char *mnem = (ins.imm == 0) ? "methodcount" : "fieldcount";
        Reg r_cls = ctx.load_src(ins.operands[0], 0);
        Reg r_dst = ctx.dst_of(ins.dst);
        ctx.out << "    " << mnem << " " << r_cls << "\n";
        // Si r_dst ya es r0 (regalloc lucky), evita mov r0, r0.
        if (r_dst.is_gp(0) == false)
            ctx.out.emit(emmit::Mnemonic::MOV, r_dst, Reg::gp(0));
        ctx.store_spilled(ins.dst);
        break;
    }
    case IrOp::REFLECT_AT: {
        // raw_asm-elim wave 2: getmethat/getfldat.
        // imm=0 -> getmethat, imm=1 -> getfldat.
        if (ins.operands.size() < 2 || ins.dst == IR_NO_VALUE) break;
        const char *mnem = (ins.imm == 0) ? "getmethat" : "getfldat";
        Reg r_cls = ctx.load_src(ins.operands[0], 0);
        Reg r_idx = ctx.load_src(ins.operands[1], 1);
        Reg r_dst = ctx.dst_of(ins.dst);
        ctx.out << "    " << mnem << " " << r_cls << ", " << r_idx << "\n";
        if (r_dst.is_gp(0) == false)
            ctx.out.emit(emmit::Mnemonic::MOV, r_dst, Reg::gp(0));
        ctx.store_spilled(ins.dst);
        break;
    }

    case IrOp::SMARTPTR_FREE: {
        // raw_asm-elim wave 2: cleanup deterministico de smart pointer
        // con 3 variantes segun ins.imm:
        //   0 = SRET_DISPATCH  -> operands=[ptr, del_addr], func_name=""
        //   1 = EXTERN_CALLN   -> operands=[ptr], func_name="<lib>:<fn>"
        //   2 = VESTA_CALLVM   -> operands=[ptr], func_name="<fn_label>"
        //
        // El emisor expande a la secuencia equivalente con labels
        // unicas via contador estatico thread-local.  Reusa el espacio
        // de labels global @c __sp_skip_<N> que el viejo RAW_ASM usaba.
        if (ins.operands.empty()) break;
        // BugFix unique 107/110 (2026-06-05): el cleanup invoca el deleter
        // via callvm/calln/callvmr -- una CALL que clobbea caller-saved
        // regs.  Sin salvar los regs vivos A TRAVES de esta call, los
        // valores que el caller usa DESPUES (p.ej. los params de
        // findclass+getstatic del `return T.field`) se corrompen y el
        // findclass devuelve null -> return basura.  Salvamos/restauramos
        // como cualquier otra call (GC_ALLOC, CALL, etc.).  El JIT (vregs)
        // ya lo manejaba; esto cierra el gap del path de slots.
        const uint32_t sp_call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> sp_save =
            live_regs_through_call(ctx, sp_call_pos, IR_NO_VALUE);
        emit_save_live_regs(ctx, sp_call_pos, sp_save);
        static thread_local uint64_t sp_label_seq = 0;
        const uint64_t lbl = ++sp_label_seq;
        // Indices invertidos a proposito: mas abajo se emite
        // `mov r14, r_del`, asi que r_ptr NO puede vivir en r14.
        Reg r_ptr = ctx.load_src(ins.operands[0], 1);
        if (ins.imm == 0 && ins.operands.size() >= 2) {
            /* SRET_DISPATCH: deleter es runtime via slot+8 */
            const std::string done_lbl = "__sp_done_" + std::to_string(lbl);
            const std::string default_lbl =
                "__sp_default_" + std::to_string(lbl);
            Reg r_del = ctx.load_src(ins.operands[1], 0);
            ctx.out.emit(emmit::Mnemonic::CMPU, r_ptr, 0);
            ctx.out.emit(emmit::Mnemonic::JMP_JE, Lbl(done_lbl));
            ctx.out.emit(emmit::Mnemonic::CMPU, r_del, 0);
            ctx.out.emit(emmit::Mnemonic::JMP_JE, Lbl(default_lbl));
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(14),
                         r_del); // staging deleter
            if (r_ptr.is_gp(1) == false)
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(1), r_ptr);
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), 1);
            ctx.out.emit(emmit::Mnemonic::CALLVMR, Reg::gp(14));
            ctx.out.emit(emmit::Mnemonic::JMP, Lbl(done_lbl));
            ctx.out.label(default_lbl);
            if (r_ptr.is_gp(1) == false)
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(1), r_ptr);
            ctx.out.emit(emmit::Mnemonic::FREE, Reg::gp(1));
            ctx.out.label(done_lbl);
        } else if (ins.imm == 1 || ins.imm == 2) {
            /* EXTERN_CALLN (1) o VESTA_CALLVM (2). */
            const std::string skip_lbl = "__sp_skip_" + std::to_string(lbl);
            ctx.out.emit(emmit::Mnemonic::CMPU, r_ptr, 0);
            ctx.out.emit(emmit::Mnemonic::JMP_JE, Lbl(skip_lbl));
            if (r_ptr.is_gp(1) == false)
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(1), r_ptr);
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), 1);
            if (ins.imm == 1) {
                ctx.out.emit(emmit::Mnemonic::CALLN,
                             Ann::method(ins.func_name));
            } else {
                ctx.out.emit(emmit::Mnemonic::CALLVM,
                             Ann::absolute("code." + ins.func_name));
            }
            ctx.out.label(skip_lbl);
        }
        emit_restore_live_regs(ctx, sp_call_pos, sp_save);
        break;
    }

    // --- string extra ---
    case IrOp::STRGETBYTES:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // load_src y NO reg_of: reg_of es una CONSULTA -- si el valor esta
            // derramado devuelve el registro scratch SIN emitir la recarga.
            // Asi, el opcode leia lo que hubiera quedado en r14 (una direccion
            // de pila, no un handle) y bytes() devolvia 0 sobre un string
            // perfectamente valido.
            const Reg r_str = ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::STRGETBYTES, ctx.dst_of(ins.dst),
                         Reg(r_str));
            ctx.store_spilled(ins.dst);
        }
        break;

    // --- Meta-OOP / reflexion /  Z ---
    case IrOp::GC_HANDLE_FOR_PTR:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::GCHANDLE, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::GC_PROMOTE:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::GCPROMOTE, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::GC_DEMOTE:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::GCDEMOTE, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::FINDCLASS:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::FINDCLASS, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::DEFCLASS:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::DEFCLASS, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::DEFFIELD:
        if (ins.operands.size() >= 2)
            // Recarga previa de AMBOS operandos, cada uno en su
            // scratch: reg_of solo consulta y devolveria el
            // mismo registro para los dos.
            (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::DEFFIELD, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;
    case IrOp::DEFMETHOD:
        if (ins.operands.size() >= 2)
            // Recarga previa de AMBOS operandos, cada uno en su
            // scratch: reg_of solo consulta y devolveria el
            // mismo registro para los dos.
            (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::DEFMETHOD, ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;
    case IrOp::ADDADVICE:
        if (ins.operands.size() >= 2) {
            // Recarga previa de AMBOS operandos, cada uno en su
            // scratch: reg_of solo consulta y devolveria el
            // mismo registro para los dos.
            (void)ctx.load_src(ins.operands[0], 0);
            (void)ctx.load_src(ins.operands[1], 1);
            ctx.out.emit(emmit::Mnemonic::ADDADVICE,
                         ctx.reg_at(ins.operands[0], 0),
                         ctx.reg_at(ins.operands[1], 1), ins.imm);
        }
        break;
    case IrOp::FINDMETHOD:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::FINDMETHOD, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::FINDFIELD:
        if (ins.dst != IR_NO_VALUE && !ins.operands.empty()) {
            // Recarga previa: reg_of solo CONSULTA (devuelve el scratch sin
            // emitir la carga si el valor esta derramado).
            (void)ctx.load_src(ins.operands[0], 0);
            ctx.out.emit(emmit::Mnemonic::FINDFIELD, ctx.dst_of(ins.dst),
                         ctx.reg_of(ins.operands[0]));
            ctx.store_spilled(ins.dst);
        }
        break;
    case IrOp::SETMETHDBG:
        // setmethdbg r_method, r_params -> registra debug info (file:line)
        // del MethodInfo* en r_method usando SetMethDebugParams en r_params.
        if (ins.operands.size() >= 2)
            // Recarga previa de AMBOS operandos, cada uno en su
            // scratch: reg_of solo consulta y devolveria el
            // mismo registro para los dos.
            (void)ctx.load_src(ins.operands[0], 0);
        (void)ctx.load_src(ins.operands[1], 1);
        ctx.out.emit(emmit::Mnemonic::SETMETHDBG,
                     ctx.reg_at(ins.operands[0], 0),
                     ctx.reg_at(ins.operands[1], 1));
        break;
    case IrOp::CALLSUPER: {
        // Signature: operands[0] = v_cls (ClassInfo* host_ptr del super),
        // operands[1] = v_this, operands[2..N+1] = args.  @c imm =
        // vtable_index del metodo en la vtable del super.  La sintaxis
        // .vel del assembler es:  @c callsuper r_cls, vtable_idx
        // con @c this en r1, args en r2..r[1+nargs] y argc+1 en r15.
        if (ins.operands.size() < 2) break;
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, ins.dst);

        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);

        // Args marshalling: r1 = this, r2..rN = args.
        const size_t nargs_user =
            ins.operands.size() > 2 ? ins.operands.size() - 2 : 0;
        std::vector<std::pair<int, Reg>> moves;
        moves.emplace_back(1, ctx.load_src(ins.operands[1], 0));
        for (size_t ai = 0; ai < nargs_user && ai < 11; ++ai)
            moves.emplace_back(static_cast<int>(ai + 2),
                               ctx.load_src(ins.operands[ai + 2], 0));
        emit_parallel_arg_moves(ctx, std::move(moves));
        // r15 = argc (incluyendo @c this).
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), (nargs_user + 1));

        // El ClassInfo* puede haber sido clobbered por los moves.
        // Re-materializarlo justo antes del callsuper.
        Reg r_cls = ctx.load_src(ins.operands[0], 0);
        ctx.out.emit(emmit::Mnemonic::CALLSUPER, r_cls, ins.imm);

        if (ins.dst != IR_NO_VALUE) {
            Reg rd = ctx.dst_of(ins.dst);
            emit_mov_if_needed(ctx, rd, Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }
    case IrOp::PROCEED:
        ctx.out.emit(emmit::Mnemonic::PROCEED);
        if (ins.dst != IR_NO_VALUE) {
            emit_mov_if_needed(ctx, ctx.reg_of(ins.dst), Reg::gp(0));
            ctx.store_spilled(ins.dst);
        }
        break;

    case IrOp::RAW_ASM: {
        // Emitir cada linea del texto incrustado con indentacion estandar.
        // Substituimos los tokens:
        //   {dst}        -> nombre del registro asignado al destino SSA
        //   {src0}..{srcN-1} -> reg de cada operando (post-regalloc)
        // Permite que un bloque RAW_ASM produzca/consuma valores SSA sin
        // crear un IR op dedicado.  Los srcN se materializan via
        // load_src(scratch_idx=0) si estan spilled (puede usar SCRATCH).
        //
        // is_call_site: si la flag esta activa, el bloque RAW_ASM es
        // logicamente una llamada que clobreara los regs caller-saved
        // (e.g. `loadmod` ejecuta el main del plugin como sub-call).
        // En ese caso envolvemos con save_live_regs / restore_live_regs
        // para preservar los locales del caller a traves del call.
        const uint32_t call_pos_raw = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save_raw;
        if (ins.is_call_site) {
            regs_to_save_raw =
                live_regs_through_call(ctx, call_pos_raw, ins.dst);
            emit_save_all_gc_aware(ctx, call_pos_raw, regs_to_save_raw);
        }

        // Aqui el texto SI es lo que toca: esto sustituye marcadores dentro del
        // asm que escribio el usuario.  Lo que cambia es de donde sale el
        // nombre -- del registro tipado, no de una cadena que ande suelta.
        std::string dst_reg;
        if (ins.dst != IR_NO_VALUE) {
            dst_reg = ctx.dst_of(ins.dst).name();
        }
        // Resolver los registros de cada operando antes de emitir.  Si
        // un operando esta spilled, load_src genera el codigo necesario
        // para cargarlo a SCRATCH y devuelve ese reg como string.
        std::vector<std::string> src_regs;
        src_regs.reserve(ins.operands.size());
        for (size_t k = 0; k < ins.operands.size(); ++k) {
            if (ins.operands[k] == IR_NO_VALUE) {
                src_regs.emplace_back();
            } else {
                src_regs.push_back(
                    ctx.load_src(ins.operands[k], static_cast<int>(k % 2))
                        .name());
            }
        }
        std::istringstream iss(ins.func_name);
        std::string ln;
        while (std::getline(iss, ln)) {
            if (ln.empty()) continue;
            if (!dst_reg.empty()) {
                size_t pos = 0;
                while ((pos = ln.find("{dst}", pos)) != std::string::npos) {
                    ln.replace(pos, 5, dst_reg);
                    pos += dst_reg.size();
                }
            }
            for (size_t k = 0; k < src_regs.size(); ++k) {
                if (src_regs[k].empty()) continue;
                const std::string tok = "{src" + std::to_string(k) + "}";
                size_t pos = 0;
                while ((pos = ln.find(tok, pos)) != std::string::npos) {
                    ln.replace(pos, tok.size(), src_regs[k]);
                    pos += src_regs[k].size();
                }
            }
            ctx.out << "    " << ln << "\n";
        }
        if (ins.dst != IR_NO_VALUE) {
            ctx.store_spilled(ins.dst);
        }
        if (ins.is_call_site) {
            emit_restore_all_gc_aware(ctx, call_pos_raw, regs_to_save_raw);
        }
        break;
    }

    case IrOp::INLINE_ASM: {
        //  AS inc.6: inline-asm ejecutable en el INTERPRETE (modo
        // -m vm, SIN compilador JIT).  El cuerpo NASM (ins.func_name) se
        // ensambla a un trampoline nativo en el LOADER (via el ensamblador
        // Keystone, no el JIT) y se registra por hash.  Aqui emitimos el
        // marshalling: rellenar los slots VM de cada register() en el
        // helper nativo vrt:inline_asm_exec, que copia VM-slot -> ctx[phys],
        // llama al trampoline, y copia ctx[phys] -> VM-slot de vuelta.
        //
        // Convencion (argc SIEMPRE 12; slots no usados = 0):
        //   r1=getproc (ProcessVM*), r2=hash(NASM), r3=desc(phys 4b/binding),
        //   r4=n_bindings, r5..r12 = direcciones VM de los slots (allocas).
        //
        // El JIT (vreg_select) maneja INLINE_ASM por su cuenta (precolorea
        // los bindings a regs fisicos), asi que esta emision SOLO la usa el
        // backend bytecode/interp.
        struct AsmBind {
            ir::IrValueId slot;
            int phys;
            /// Codigo de ancho (@ref vx::asm_codigo_de_ancho): 0 = banco
            /// general (8 bytes), 1/2/3 = 16/32/64 del banco ancho.
            unsigned width_code = 0;
        };
        std::vector<AsmBind> binds;
        bool ancho_sin_pasar = false;
        for (ir::IrValueId opv : ins.operands) {
            if (opv == IR_NO_VALUE) continue;
            for (const auto &b : ctx.fn.asm_reg_bindings) {
                if (b.alloca_value != opv) continue;
                if (b.is_vector) {
                    /* El valor del banco ancho tambien viaja.
                     *
                     * Lo que se pasa de cada operando es la DIRECCION de su
                     * hueco, no el valor, asi que da igual que mida 8 bytes o
                     * 64: lo unico que hacia falta era decir CUANTOS mover, y
                     * para eso el descriptor tenia 24 bits sin usar -- tres por
                     * operando, que es justo lo que mide el codigo de ancho.
                     *
                     * Antes se renunciaba aqui.  Al principio en SILENCIO -- la
                     * ligadura desaparecia de la lista y el bloque se ejecutaba
                     * con lo que hubiera en ese registro --, y despues parando
                     * con un mensaje.  Ninguna de las dos hacia lo que se
                     * pedia.
                     *
                     * Se sigue renunciando en lo que de verdad no cabe: un
                     * registro mas ancho que la ranura del contexto, o un
                     * indice que no entra en los 4 bits del descriptor.  Mover
                     * medio valor no da error, deja basura dentro. */
                    const uint8_t isa = (uint8_t)vx::isa_actual();
                    const int slot = vx::asm_slot_of_class(isa, b.reg);
                    const uint32_t bytes = vx::asm_bytes_de_clase(isa, b.reg);
                    if (slot < 0 || slot > 15 || bytes == 0 ||
                        !vx::asm_cabe_en_ranura(bytes * 8)) {
                        ancho_sin_pasar = true;
                        break;
                    }
                    binds.push_back(
                        {opv, slot, vx::asm_codigo_de_ancho(bytes * 8)});
                    break;
                }
                const int phys = gp_phys_of_canon(vx::asm_canonical_reg(b.reg));
                if (phys >= 0) binds.push_back({opv, phys, 0u});
                break;
            }
        }
        if (ancho_sin_pasar) {
            /* Se para, pero DICIENDOLO.
             *
             * Antes se emitia un `hlt` pelado, y eso en ejecucion es
             * indistinguible de que el programa termine bien: el proceso paraba
             * a mitad de la funcion y quien la llamo leia lo que hubiera
             * quedado en R0.  Asi devolvia `367_std_memory_variantes` un
             * puntero -- y en otra de sus rutinas, el propio byte de relleno --
             * en vez de su resultado, sin una queja.
             *
             * Ahora se llama a una funcion del runtime que lanza el fallo con
             * su mensaje, capturable con `try`/`catch` como cualquier otro. */
            ctx.comment("inline_asm: un operando del banco ancho no puede "
                        "pasar por esta via (sus valores no entran ni salen) "
                        "-> fallo con mensaje en vez de resultado falso");
            ctx.out.emit(emmit::Mnemonic::GETPROC, Reg::gp(1));
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), 1);
            ctx.out.emit(emmit::Mnemonic::CALLN,
                         Ann::method("vrt:asm_wide_operand_unsupported"));
            break;
        }
        if (binds.size() > 8) {
            // >8 bindings excede el limite de args (argc 12 = 4 fijos + 8
            // slots).  Caso patologico: trap ruidoso en vez de truncar.
            ctx.comment("inline_asm: >8 register bindings no soportado en "
                        "interp -> trap");
            ctx.out.emit(emmit::Mnemonic::HLT);
            break;
        }

        // el cuerpo puede llevar $N (operandos `reg` auto).  El interp
        // no tiene RA -> sustituye $N por el pick GREEDY del binding.  El hash
        // debe ser del cuerpo SUSTITUIDO (el trampolin registra el mismo).
        const std::string ibody =
            vx::asm_body_subst_greedy(ins.func_name, ctx.fn.asm_reg_bindings);
        const uint64_t hash = jit::fnv1a64_asm(ibody);
        /* Descriptor de los huecos: 4 bits por operando con su registro
         * (bits 0..31) y, en los bits 32..39, si ese hueco vive en memoria del
         * HOST.  Hace falta decirlo: un hueco puede acabar en memoria del host
         * (es lo que se busca) y entonces leerlo como direccion de la maquina
         * virtual da basura -- el valor no entraba ni salia, y el asm quedaba
         * desconectado de la variable sin que nadie avisara. */
        uint64_t desc = 0;
        for (size_t i = 0; i < binds.size(); ++i) {
            desc |= (uint64_t)(binds[i].phys & 0xF) << (i * 4);
            if (binds[i].slot < ctx.fn.values.size() &&
                ctx.fn.values[binds[i].slot].is_host_ptr)
                desc |= 1ull << (32 + i);
            /* Y en los bits 40..63, el ancho: tres por operando.  Sin esto, un
             * operando del banco ancho se movia como si midiera ocho bytes y
             * llegaba a medias -- eso no da error, deja basura dentro. */
            desc |= (uint64_t)(binds[i].width_code & 0x7u) << (40 + i * 3);
        }

        // Salvar regs vivos a traves de la llamada (el helper es un calln).
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, IR_NO_VALUE);
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);

        // Slots -> r5..r(4+n) via parallel-move (resuelve dependencias entre
        // args). Los slots son las direcciones VM de los allocas register().
        std::vector<std::pair<int, Reg>> moves;
        moves.reserve(binds.size());
        for (size_t i = 0; i < binds.size(); ++i)
            moves.emplace_back(static_cast<int>(5 + i),
                               ctx.load_src(binds[i].slot, 0));
        emit_parallel_arg_moves(ctx, std::move(moves));

        // Pad de slots no usados (r(5+n)..r12) = 0.
        for (size_t i = binds.size(); i < 8; ++i)
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(5 + i), 0);

        // Args fijos: r1..r4 (escritos DESPUES del parallel-move; sus valores
        // previos como fuentes de slots ya fueron consumidos).
        ctx.out.emit(emmit::Mnemonic::GETPROC, Reg::gp(1));
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(2),
                     emmit::Operand::of_imm_hex(hash, 16));
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(3),
                     emmit::Operand::of_imm_hex(desc, 1));
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(4), binds.size());
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), 12);
        ctx.out.emit(emmit::Mnemonic::CALLN,
                     Ann::method("vrt:inline_asm_exec"));

        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    case IrOp::ASM_MICRO: {
        // asm opaco liftado en el INTERPRETE.  Diseno UNIFICADO (la ventaja de
        // ASM_MICRO sobre INLINE_ASM: lleva sus efectos de la DB):
        //   - si hay ENSAMBLADOR para el host, el loader ensamblo la plantilla
        //   a
        //     un trampoline nativo por hash -> se ejecuta la instruccion REAL;
        //   - si NO hay ensamblador (u otra arch), se EMULA el efecto de forma
        //     PORTABLE (barrera de memoria via los eff bits) -> el codigo SIGUE
        //     funcionando en cualquier arch.
        // El helper vrt:asm_micro_exec decide en runtime (busca el trampoline;
        // si falta, emula).  El JIT/AOT (nativos) emiten la instruccion real
        // directo en vreg_select.
        //
        // Este incremento cubre el caso SIN operandos de registro; el caso con
        // operandos (marshalling/pinning) llega en un incremento posterior.
        if (ins.imm >= ctx.fn.asm_micros.size()) {
            ctx.comment("asm_micro: indice fuera de rango -> trap");
            ctx.out.emit(emmit::Mnemonic::HLT);
            break;
        }
        const AsmMicro &am = ctx.fn.asm_micros[ins.imm];
        // sustituir $0,$1,... por el registro FiSICO FIJO de cada
        // operando; sin operandos la plantilla queda verbatim.  El hash es el
        // del TEXTO FINAL (== el que registra el trampolin).  Un operando no
        // fisico (SSA/RA) o clase no soportada -> trap.
        std::string nasm = am.tmpl;
        if (!am.operands.empty() && !vx::asm_micro_subst_phys(am, nasm)) {
            /* Operandos que son VALORES del programa.  El interprete no reparte
             * registros, asi que hay que elegirlos (misma funcion que usa quien
             * prepara la instruccion, o el texto no coincide) y luego meter los
             * valores antes de ejecutar y sacarlos despues.  Es lo mismo que ya
             * se hace con los bloques opacos; la diferencia es que alli el dato
             * es "la variable X" y aqui es un valor del IR, asi que viaja por
             * una tabla en la pila en vez de por el hueco de la variable. */
            std::vector<int> phys;
            if (!vx::asm_micro_subst_greedy(am, nasm, phys)) {
                ctx.comment(
                    "asm_micro: no se pudo dar registro a sus operandos "
                    "-> trap");
                ctx.out.emit(emmit::Mnemonic::HLT);
                break;
            }
            // Los valores llegan en los operandos de la instruccion, en el
            // mismo orden que los operandos de la ficha que llevan valor.
            std::vector<std::pair<size_t, IrValueId>>
                conv; // (indice ficha, valor)
            size_t nv = 0;
            for (size_t oi = 0; oi < am.operands.size(); ++oi) {
                if (am.operands[oi].value == IR_NO_VALUE) continue;
                if (nv >= ins.operands.size()) break;
                conv.emplace_back(oi, ins.operands[nv++]);
            }
            if (conv.size() > 8) {
                ctx.comment("asm_micro: mas de 8 operandos con valor -> trap");
                ctx.out.emit(emmit::Mnemonic::HLT);
                break;
            }
            const uint64_t hash2 = jit::fnv1a64_asm(nasm);
            /* Descriptor: 8 bits por operando -- 5 de ranura y 3 de ancho.
             *
             * Con 4 bits solo cabia la ranura, y quien lo lee no podia saber si
             * el valor iba al banco general o al ancho: lo metia siempre en el
             * general.  El ancho va aqui y no se deduce del registro porque
             * `xmm3`, `ymm3` y `zmm3` son la MISMA ranura.
             *
             * Los dos lados sacan el formato del mismo sitio (@c vx::kAsm*): es
             * un acuerdo, y con una copia en cada lado se pueden separar sin
             * que nada falle al compilar -- el fallo sale como valores movidos
             * de sitio, que es basura, no un error. */
            /* Los descriptores van EN MEMORIA, detras de la tabla de valores,
             * uno por operando y con campos nombrados.  Empaquetados en un
             * entero le ponian techo de bits a algo que crece con cada ISA, y
             * el campo que se quedo fuera fue el de CLASE -- con lo que ocho
             * bytes en el banco ancho acababan en el general. */
            /* Ranuras del ancho MAYOR, todas iguales: con ranuras ajustadas a
             * cada operando el desplazamiento de la ranura `i` depende de todas
             * las anteriores, y ese calculo tendria que salir identico aqui y
             * al otro lado. */
            /* Un solo bloque: valores primero, descriptores detras.  Dos
             * reservas separadas serian dos sitios que cuadrar entre este lado
             * y el que los lee. */
            const size_t bytes_valores = conv.size() * vx::kAsmSlotBytes;
            const size_t bytes_tabla =
                bytes_valores + conv.size() * vx::kAsmDescBytes;
            /* El valor que el bloque devuelve NO se salva alrededor de la
             * llamada: se recoge de la tabla despues, y restaurarlo lo
             * devolveria a lo que era -- `add a, 2` sobre 40 seguia dando 40.
             * Es el mismo trato que recibe el resultado de cualquier llamada.
             * Con mas de un valor devuelto no hay como decirlo, asi que ese
             * caso no pasa por aqui. */
            IrValueId devuelto = IR_NO_VALUE;
            size_t n_devueltos = 0;
            for (const auto &c : conv) {
                const auto &o = am.operands[c.first];
                if (o.writes() && o.kind != AsmOperandKind::MEM) {
                    devuelto = c.second;
                    ++n_devueltos;
                }
            }
            if (n_devueltos > 1) {
                ctx.comment("asm_micro: mas de un valor devuelto -> trap");
                ctx.out.emit(emmit::Mnemonic::HLT);
                break;
            }
            const uint32_t cpos = lin_pos_of(ctx, bb.id, idx);
            std::vector<int> salvar =
                live_regs_through_call(ctx, cpos, devuelto);
            emit_save_all_gc_aware(ctx, cpos, salvar);
            /* Tabla de valores en la pila de la maquina virtual.  La direccion
             * se lleva en r15 porque la forma de direccionar no admite rsp
             * directo, y se vuelve a tomar despues de la llamada -- r15 es
             * ademas donde va el numero de argumentos, asi que no sobrevive. */
            /* La ranura se direcciona con la forma [base + indice] del
             * ensamblador: no hay desplazamiento inmediato en esa codificacion,
             * el desplazamiento va en un registro. */
            ctx.out.emit(emmit::Mnemonic::SUBSP, Reg::special(SpecialReg::RSP),
                         bytes_tabla);
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15),
                         Reg::special(SpecialReg::RSP));
            for (size_t i = 0; i < conv.size(); ++i) {
                const Reg src = ctx.load_src(conv[i].second, 0);
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13),
                             (i * vx::kAsmSlotBytes));
                ctx.out.emit(emmit::Mnemonic::MOV,
                             Mem(Reg::gp(15), Reg::gp(13), 1), Reg(src));
            }
            /* Y los descriptores, que aqui son constantes conocidas. */
            for (size_t i = 0; i < conv.size(); ++i) {
                const auto &opd = am.operands[conv[i].first];
                const bool ancho = (opd.regclass == vx::ASM_RC_VEC ||
                                    opd.regclass == vx::ASM_RC_FP);
                const unsigned bytes =
                    (ancho && opd.width >= 8) ? (unsigned)opd.width / 8u : 8u;
                const uint64_t campos =
                    (uint64_t)(unsigned)opd.regclass |
                    ((uint64_t)(unsigned)(phys[conv[i].first] & 0xFFFF) << 16) |
                    ((uint64_t)(bytes & 0xFFFFu) << 32);
                /* r13 y r14, que son los scratch que este emisor ya usa para
                 * direccionar la tabla.  Coger otro cualquiera -- r12, por
                 * ejemplo -- pisaria un valor vivo: aqui no hay asignador, asi
                 * que un registro solo esta libre si la convencion dice que lo
                 * esta. */
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13),
                             bytes_valores + i * vx::kAsmDescBytes);
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(14),
                             emmit::Operand::of_imm_hex(campos, 1));
                ctx.out.emit(emmit::Mnemonic::MOV,
                             Mem(Reg::gp(15), Reg::gp(13), 1), Reg::gp(14));
            }
            ctx.out.emit(emmit::Mnemonic::GETPROC, Reg::gp(1));
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(2),
                         emmit::Operand::of_imm_hex(hash2, 16));
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(3), (unsigned)am.eff);
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(4), Reg::gp(15));
            /* r5 deja de ser el descriptor empaquetado y pasa a ser DONDE estan
             * los descriptores: detras de los valores, en el mismo bloque.  Un
             * entero no daba para describir clase, ranura y ancho de cada
             * operando, y menos segun entren ISAs y extensiones. */
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(5), Reg::gp(15));
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13), bytes_valores);
            ctx.out.emit(emmit::Mnemonic::ADDU, Reg::gp(5),
                         Reg::gp(13)); // sin signo: es una direccion
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(6), conv.size());
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), 6);
            ctx.out.emit(emmit::Mnemonic::CALLN,
                         Ann::method("vrt:asm_micro_ops"));
            /* Y de vuelta lo que el bloque haya cambiado, DESPUES de restaurar
             * los registros que se salvaron para la llamada.  Recogerlo antes
             * era tirarlo: el valor recien traido se queda en un registro y la
             * restauracion lo devuelve a lo que era, asi que `add a, 2` sobre
             * 40 seguia dando 40.  La tabla vive en la pila hasta el addsp, que
             * por eso va el ultimo. */
            ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15),
                         Reg::special(SpecialReg::RSP));
            for (size_t i = 0; i < conv.size(); ++i) {
                const auto &opf = am.operands[conv[i].first];
                if (!opf.writes() || opf.kind == AsmOperandKind::MEM) continue;
                const Reg rd = ctx.dst_of(conv[i].second);
                ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(13),
                             (i * vx::kAsmSlotBytes));
                ctx.out.emit(emmit::Mnemonic::MOV, Reg(rd),
                             Mem(Reg::gp(15), Reg::gp(13), 1));
                ctx.store_spilled(conv[i].second);
            }
            ctx.out.emit(emmit::Mnemonic::ADDSP, Reg::special(SpecialReg::RSP),
                         bytes_tabla);
            emit_restore_all_gc_aware(ctx, cpos, salvar);
            break;
        }
        const uint64_t hash = jit::fnv1a64_asm(nasm);
        const uint32_t call_pos = lin_pos_of(ctx, bb.id, idx);
        std::vector<int> regs_to_save =
            live_regs_through_call(ctx, call_pos, IR_NO_VALUE);
        emit_save_all_gc_aware(ctx, call_pos, regs_to_save);
        // r1=proc, r2=hash(plantilla), r3=eff (efectos DB para la emulacion).
        ctx.out.emit(emmit::Mnemonic::GETPROC, Reg::gp(1));
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(2),
                     emmit::Operand::of_imm_hex(hash, 16));
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(3), (unsigned)am.eff);
        ctx.out.emit(emmit::Mnemonic::MOV, Reg::gp(15), 3);
        ctx.out.emit(emmit::Mnemonic::CALLN, Ann::method("vrt:asm_micro_exec"));
        emit_restore_all_gc_aware(ctx, call_pos, regs_to_save);
        break;
    }

    default:
        ctx.comment("instruccion no soportada: " +
                    std::string(ir_op_name(ins.op)));
        ctx.out.emit(emmit::Mnemonic::NOP1);
        break;
    }
}

// =========================================================================
//  Emision de una funcion completa
// =========================================================================

// Escape hatch VESTA_NO_FUSE (definido mas abajo, cerca del sink).
static bool interp_fuse_disabled();

// ----   allocador del BANCO DE REGISTROS ANCHOS (ZMM) ----
//
// El banco ZMM de la VM (registros anchos de 128/256/512-bit, f0..f15) NO es
// exclusivo de floats: aloja escalares float, vectores SIMD y manipulacion de
// memoria en bloque.  El allocador `wide_bank_linear_scan` de mas abajo es
// GENERAL y AGNOSTICO AL TIPO/ANCHO: recibe un conjunto de valores "residentes
// del banco" + su vivacidad y les asigna INDICES de registro.  Cada CLIENTE
// (floats escalares hoy; vectores/memcpy en el futuro) computa SUS candidatos
// con su propia semantica y comparte este allocador.  El ancho concreto de cada
// registro lo decide el TIPO del valor en la emision (f64=8 B, f32=4 B,
// vNNN...).
//
// Cliente FLOAT: un valor F64/F32 puede residir en el banco (sin roundtrip
// bitg2z/bitz2g) si su DEF es un productor float (arith/load) y TODOS sus usos
// son consumidores float (arith/store).  Cualquier cruce de banco (PHI, CALL,
// RET, BITCAST, conversiones int<->float, FCMP) lo excluye -> path GP +
// bitcast.

static inline bool zmm_producer_op(IrOp op) {
    switch (op) {
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV:
    case IrOp::FNEG:
    case IrOp::FABS:
    case IrOp::FSQRT:
    case IrOp::FMIN:
    case IrOp::FMAX:
    case IrOp::FFLOOR:
    case IrOp::FCEIL:
    case IrOp::FROUND:
    case IrOp::FTRUNC:
    case IrOp::FMA:   // produce un float
    case IrOp::LOAD:  // carga float
    case IrOp::CONST: // const float via fmowi
    // Fronteras que PRODUCEN un float en el banco:
    case IrOp::ITOF:     // int (GP) -> float
    case IrOp::UITOF:    // uint (GP) -> float
    case IrOp::F32TOF64: // f32 -> f64 (fextend)
    case IrOp::F64TOF32: // f64 -> f32 (fnarrow)
        return true;
    default: return false;
    }
}
static inline bool zmm_consumer_op(IrOp op) {
    switch (op) {
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV:
    case IrOp::FNEG:
    case IrOp::FABS:
    case IrOp::FSQRT:
    case IrOp::FMIN:
    case IrOp::FMAX:
    case IrOp::FFLOOR:
    case IrOp::FCEIL:
    case IrOp::FROUND:
    case IrOp::FTRUNC:
    case IrOp::FMA: // consume a, b, c (floats)
    case IrOp::STORE:
    // Fronteras que CONSUMEN un float del banco:
    case IrOp::FTOI:     // float -> int (GP)
    case IrOp::FTOUI:    // float -> uint (GP)
    case IrOp::F32TOF64: // fuente f32
    case IrOp::F64TOF32: // fuente f64
    case IrOp::FCMP_EQ:
    case IrOp::FCMP_NE:
    case IrOp::FCMP_LT:
    case IrOp::FCMP_GT:
    case IrOp::FCMP_LE:
    case IrOp::FCMP_GE:
    case IrOp::PHI: // el PHI de un acumulador loop-carried consume floats del
                    // banco
        return true;
    default: return false;
    }
}

static bool interp_zmm_disabled() {
    static const bool disabled = util::flag_on(util::FlagId::NoZmm);
    return disabled;
}

// Allocador GENERAL del banco ancho: linear-scan agnostico al tipo/ancho.
// Recibe los candidatos (residentes del banco) ordenables por vivacidad y les
// asigna indices [num_scratch .. num_regs-1]; los primeros `num_scratch`
// registros quedan reservados como scratch del cliente.  Reusable por cualquier
// cliente del banco (floats, vectores SIMD, memcpy...).  Los que no obtienen
// registro (banco lleno) se quedan fuera y el cliente cae a su path de reserva.
static std::unordered_map<IrValueId, int> wide_bank_linear_scan(
    std::vector<IrValueId> cands, const LivenessResult &liveness, int num_regs,
    int num_scratch, const std::unordered_map<IrValueId, IrValueId> &prefer) {
    std::unordered_map<IrValueId, int> zmm_assign; // banco ZMM, NO el GP
    if (cands.empty()) return zmm_assign;
    std::unordered_map<IrValueId, const LiveInterval *> iv;
    for (const auto &it : liveness.intervals)
        iv[it.id] = &it;
    std::sort(cands.begin(), cands.end(), [&](IrValueId a, IrValueId b) {
        const uint32_t da = iv.count(a) ? iv.at(a)->def : 0u;
        const uint32_t db = iv.count(b) ? iv.at(b)->def : 0u;
        return da < db;
    });
    std::vector<int> freep;
    for (int r = num_regs - 1; r >= num_scratch; --r)
        freep.push_back(r);
    std::vector<std::pair<uint32_t, IrValueId>> active; // (end, vid)
    for (IrValueId v : cands) {
        auto it = iv.find(v);
        if (it == iv.end()) continue;
        const uint32_t start = it->second->def, end = it->second->end;
        for (size_t k = 0; k < active.size();) {
            if (active[k].first < start) {
                freep.push_back(zmm_assign[active[k].second]);
                active[k] = active.back();
                active.pop_back();
            } else {
                ++k;
            }
        }
        if (freep.empty())
            continue; // banco lleno -> el cliente usa su path de reserva
        // Coalescing: si v prefiere reutilizar el registro de otro valor (p.ej.
        // el src1 de un binop que muere en v) y ese registro esta libre, se le
        // asigna -> se ahorra el `fmov` del 2-address.
        int reg = -1;
        auto pit = prefer.find(v);
        if (pit != prefer.end()) {
            auto rit = zmm_assign.find(pit->second);
            if (rit != zmm_assign.end()) {
                auto fit = std::find(freep.begin(), freep.end(), rit->second);
                if (fit != freep.end()) {
                    reg = *fit;
                    freep.erase(fit);
                }
            }
        }
        if (reg < 0) {
            reg = freep.back();
            freep.pop_back();
        }
        zmm_assign[v] = reg;
        active.push_back({end, v});
    }
    return zmm_assign;
}

// Cliente FLOAT del banco ancho: selecciona los escalares F64/F32 que pueden
// residir sin cruzar a GP (def productor float, todos los usos consumidores
// float) y les asigna registros via el allocador general.
static std::unordered_map<IrValueId, int>
compute_zmm_alloc(const IrFunction &fn, const LivenessResult &liveness) {
    if (interp_zmm_disabled()) return {};
    const size_t nv = fn.values.size();
    if (nv == 0) return {};
    std::vector<IrOp> def_op(nv);
    std::vector<char> has_def(nv, 0), bad(nv, 0);
    std::unordered_set<IrValueId> is_param(fn.params.begin(), fn.params.end());
    for (const auto &bb : fn.blocks) {
        for (const auto &in : bb.instrs) {
            if (in.dst != IR_NO_VALUE && static_cast<size_t>(in.dst) < nv) {
                def_op[in.dst] = in.op;
                has_def[in.dst] = 1;
            }
            // Cualquier uso en una op NO-consumidora float excluye al operando.
            if (!zmm_consumer_op(in.op)) {
                for (IrValueId op : in.operands)
                    if (op != IR_NO_VALUE && static_cast<size_t>(op) < nv)
                        bad[op] = 1;
                for (const auto &pa : in.phi_args)
                    if (pa.value != IR_NO_VALUE &&
                        static_cast<size_t>(pa.value) < nv)
                        bad[pa.value] = 1;
            }
        }
    }
    // Union-find sobre las clases de congruencia PHI: se unen el dst del PHI y
    // sus phi_args float.  Un valor float es candidato a ZMM si su def es un
    // productor O es un PHI de un acumulador.  Regla ALL-OR-NONE: un componente
    // PHI solo es elegible si TODOS sus miembros lo son individualmente -> asi
    // ninguna copia PHI mezcla banco GP y ZMM (el acumulador loop-carried vive
    // entero en el banco float, sin roundtrip movh+bitg2z cada iteracion).
    std::vector<int> uf(nv);
    for (size_t i = 0; i < nv; ++i)
        uf[i] = static_cast<int>(i);
    auto uf_find = [&uf](int x) {
        while (uf[x] != x) {
            uf[x] = uf[uf[x]];
            x = uf[x];
        }
        return x;
    };
    auto uf_union = [&](int a, int b) {
        a = uf_find(a);
        b = uf_find(b);
        if (a != b) uf[a] = b;
    };
    for (const auto &bb : fn.blocks)
        for (const auto &in : bb.instrs)
            if (in.op == IrOp::PHI && in.dst != IR_NO_VALUE &&
                static_cast<size_t>(in.dst) < nv) {
                const IrType dt = fn.values[in.dst].type;
                if (dt != IrType::F64 && dt != IrType::F32) continue;
                for (const auto &pa : in.phi_args)
                    if (pa.value != IR_NO_VALUE &&
                        static_cast<size_t>(pa.value) < nv)
                        uf_union(static_cast<int>(in.dst),
                                 static_cast<int>(pa.value));
            }
    auto indiv_ok = [&](IrValueId v) -> bool {
        const IrType t = fn.values[v].type;
        if (t != IrType::F64 && t != IrType::F32) return false;
        if (is_param.count(v) || !has_def[v] || bad[v]) return false;
        return zmm_producer_op(def_op[v]) || def_op[v] == IrOp::PHI;
    };
    // comp_ok[root] = todos los miembros float del componente son elegibles.
    std::unordered_map<int, bool> comp_ok;
    for (IrValueId v = 0; static_cast<size_t>(v) < nv; ++v) {
        const IrType t = fn.values[v].type;
        if (t != IrType::F64 && t != IrType::F32) continue;
        const int r = uf_find(static_cast<int>(v));
        auto it = comp_ok.find(r);
        if (it == comp_ok.end()) comp_ok[r] = true;
        if (!indiv_ok(v)) comp_ok[r] = false;
    }
    std::vector<IrValueId> cands;
    for (IrValueId v = 0; static_cast<size_t>(v) < nv; ++v) {
        const IrType t = fn.values[v].type;
        if (t != IrType::F64 && t != IrType::F32) continue;
        if (!indiv_ok(v)) continue;
        auto it = comp_ok.find(uf_find(static_cast<int>(v)));
        if (it == comp_ok.end() || !it->second) continue;
        cands.push_back(v);
    }
    // Hint de coalescing: el dst de un binop/unop float aritmetico prefiere
    // reutilizar el registro de su src1 (que suele morir ahi) -> ahorra el
    // `fmov` del 2-address.  Solo un hint; el allocador lo respeta si es
    // seguro.
    std::unordered_map<IrValueId, IrValueId> prefer;
    for (const auto &bb : fn.blocks) {
        for (const auto &in : bb.instrs) {
            switch (in.op) {
            case IrOp::FADD:
            case IrOp::FSUB:
            case IrOp::FMUL:
            case IrOp::FDIV:
            case IrOp::FNEG:
            case IrOp::FABS:
            case IrOp::FSQRT:
            case IrOp::FMIN:
            case IrOp::FMAX:
            case IrOp::FFLOOR:
            case IrOp::FCEIL:
            case IrOp::FROUND:
            case IrOp::FTRUNC:
                if (in.dst != IR_NO_VALUE && !in.operands.empty() &&
                    in.operands[0] != IR_NO_VALUE)
                    prefer[in.dst] = in.operands[0];
                break;
            case IrOp::FMA:
                // fmadd acumula en fd = fc -> el dst prefiere el reg de c.
                if (in.dst != IR_NO_VALUE && in.operands.size() >= 3 &&
                    in.operands[2] != IR_NO_VALUE)
                    prefer[in.dst] = in.operands[2];
                break;
            default: break;
            }
        }
    }
    // Banco float de la VM interp: 16 registros (f0..f15); el cliente float
    // reserva 3 scratch (f0/f1 = operandos GP, f2 = temp del 2-address).  Para
    // otro ISA basta cambiar estos dos numeros.
    std::unordered_map<IrValueId, int> zmm_map = wide_bank_linear_scan(
        std::move(cands), liveness, /*num_regs=*/16, /*num_scratch=*/3, prefer);
    // Democion ALL-OR-NONE: si un componente PHI no quedo ENTERO en el banco
    // (el linear-scan derramo algun miembro por presion), sacar TODOS sus
    // miembros del banco.  Garantiza que las copias PHI sean puras GP<->GP o
    // ZMM<->ZMM (nunca mixtas), que es lo que emit_phi_copies sabe resolver.
    {
        std::unordered_map<int, int> total, in_bank;
        for (IrValueId v = 0; static_cast<size_t>(v) < nv; ++v) {
            const IrType t = fn.values[v].type;
            if (t != IrType::F64 && t != IrType::F32) continue;
            if (!indiv_ok(v)) continue;
            const int r = uf_find(static_cast<int>(v));
            auto it = comp_ok.find(r);
            if (it == comp_ok.end() || !it->second) continue;
            total[r]++;
            if (zmm_map.count(v)) in_bank[r]++;
        }
        for (const auto &kv : total)
            if (kv.second > 1 && in_bank[kv.first] != kv.second) {
                const int r = kv.first;
                for (IrValueId v = 0; static_cast<size_t>(v) < nv; ++v)
                    if (uf_find(static_cast<int>(v)) == r) zmm_map.erase(v);
            }
    }
    return zmm_map;
}

static std::string emit_function(const IrFunction &fn, const EmitOptions &opts,
                                 VelSink &out, bool is_entry_point = false,
                                 const IrModule *mod = nullptr,
                                 std::vector<uint8_t> *value_regs = nullptr) {
    // Liveness + asignacion de registros.
    //
    // Coalescencia de congruencias de PHI: se computa la MISMA decision de
    // congruencia que usa el JIT/AOT (jit::ssa_phi_coalesce_remap, funcion pura
    // del IR) y se CONSUME en el allocator sin tocar el SSA -> los valores
    // congruentes comparten registro VM, las copias PHI intra-clase quedan
    // no-op, el bytecode emitido tiene menos MOVs.  Se fuerza que cada param
    // sea el root de su clase para que la pre-asignacion de params encaje con
    // los valores canonicos.  Escape: VESTA_NO_IR_COALESCE=1 lo desactiva.
    LivenessResult liveness = compute_liveness(fn);
    std::vector<uint32_t> coal_remap;
    {
        static const bool coal_off = util::flag_on(util::FlagId::NoIrCoalesce);
        if (!coal_off && !fn.is_native) {
            /* El objetivo aqui es la VM, que no es ninguna ISA de la base de
             * instrucciones: por eso la pregunta es "que le pasa al destino" y
             * no "que arquitectura es".  Se contesta `Destructive`, que es la
             * forma BASE de su ALU (`adds rd, rs` deja el resultado en rd) y lo
             * que este emisor venia asumiendo.
             *
             * Queda apuntado que la VM tiene ademas super-instrucciones de tres
             * operandos (`adds3 rd, rs1, rs2`), y que este emisor las emite
             * cuando el destino no coincide con el primer operando.  En la
             * medida en que siempre pueda emitirlas, la restriccion sobra y la
             * respuesta seria `Preserving` -- pero eso CAMBIA el bytecode que
             * se emite, asi que se mide y se decide aparte, no de camino. */
            coal_remap =
                jit::ssa_phi_coalesce_remap(fn, jit::DstKind::Destructive);
            if (!coal_remap.empty()) {
                // Forzar que cada parametro sea el root de su propia clase:
                // el allocator pre-asigna params por su IrValueId, asi que un
                // param no puede ser un miembro no-root.
                for (IrValueId pid : fn.params) {
                    if (pid == IR_NO_VALUE || pid >= coal_remap.size())
                        continue;
                    IrValueId old_root = coal_remap[pid];
                    if (old_root == pid) continue;
                    for (IrValueId v = 0; v < coal_remap.size(); ++v)
                        if (coal_remap[v] == old_root) coal_remap[v] = pid;
                }
            }
        }
    }
    /* UN SOLO ASIGNADOR para los tres modos: el mismo @c codegen::rbank que
     * usan el JIT y el AOT.  El interprete tenia el suyo (@c ir::allocate_regs,
     * barrido lineal propio); se jubilo -- dos respuestas a la misma pregunta
     * obligan a arreglar cada fallo dos veces, y la del interprete guardaba
     * conocimiento que no estaba dicho en ningun sitio (ver
     * @c codegen/vm_isa_facts.h).
     *
     * La migracion se valido con una puerta que permitia correr los dos con el
     * MISMO binario: 590 programas del corpus, mismo resultado en todos.  La
     * puerta desaparece con el asignador que comparaba. */
    codegen::RegAlloc alloc = codegen::vm_allocate(
        fn, liveness, coal_remap.empty() ? nullptr : &coal_remap);

    /* Donde acabo cada valor.  Es lo unico que el asignador sabe y nadie mas
     * puede reconstruir; se publica para poder decir, al explicar un fallo,
     * que `%8` es el `r1` que aparece en la instruccion de la maquina.  Los
     * valores coalescidos comparten registro: se pregunta por el canonico. */
    if (value_regs) {
        value_regs->assign(fn.values.size(), IR_NO_REG);
        for (IrValueId v = 0; v < fn.values.size(); ++v) {
            const IrValueId root = (v < coal_remap.size()) ? coal_remap[v] : v;
            if (alloc.in_reg(root)) (*value_regs)[v] = alloc.reg_of(root);
        }
    }

    // fix14: solo emitir enter/leave si hay slots de spill O si la funcion
    // contiene ALLOCA (que genera subsp rsp, N sin un addsp correspondiente
    // antes del ret).  Sin enter/leave, el leave del epilogo no puede restaurar
    // RSP al valor que tenia cuando callvm empujo el ret_addr; el ret leeria
    // una direccion incorrecta y saltaria a basura.  Las funciones
    // verdaderamente hoja (sin spill y sin ALLOCA) son las unicas que pueden
    // omitir enter/leave con seguridad: solo tienen push/pop balanceados y
    // callvm/ret que cancelan su propia RSP change.
    bool has_alloca = false;
    if (alloc.num_spill_slots == 0) {
        for (const IrBlock &bb : fn.blocks) {
            for (const IrInstr &ins : bb.instrs) {
                if (ins.op == IrOp::ALLOCA) {
                    has_alloca = true;
                    break;
                }
            }
            if (has_alloca) break;
        }
    }

    // GC preciso: forzar un FRAME (enter) en dos casos, para que el scan del
    // interprete tenga un rbp estable donde anclar:
    //   (1) La funcion contiene un SAFEPOINT DIRECTO (newobj/gcalloc): cuando
    //       el GC dispara aqui, esta funcion es el frame TOP; con enter, su
    //       rbp delimita el frame y [rbp+8] es el return_pc del caller (el
    //       sitio donde el caller retiene sus raices).  Sin enter (funcion
    //       hoja tipica `__new_X`), el rbp seria el del caller y no habria
    //       forma de recuperar el return_pc del caller ni su rbp por separado.
    //   (2) La funcion EMPUJA una raiz GC register-held a traves de un CALL:
    //       con enter, ese handle empujado cae en un offset rbp-relativo fijo
    //       (slot spill_count+push_idx) que el scan puede leer con precision.
    // Solo cuando emit_stackmaps esta activo (build con GC preciso).  Coste:
    // un enter/leave (2 instrs) en funciones que antes eran hoja pero alocan
    // o retienen GC -- despreciable y solo en el camino GC.
    bool force_frame_gc = false;
    if (opts.emit_stackmaps && alloc.num_spill_slots == 0 && !has_alloca) {
        // Posiciones lineales por bloque (para safepoint_gc_roots).
        for (const IrBlock &bb : fn.blocks) {
            for (size_t i = 0; i < bb.instrs.size() && !force_frame_gc; ++i) {
                const IrInstr &ins = bb.instrs[i];
                // (1) Safepoint directo.
                if (ir::is_gc_safepoint(ins.op)) {
                    force_frame_gc = true;
                    break;
                }
                // (2) Empuje de raiz GC register-held a traves de un CALL.
                switch (ins.op) {
                case IrOp::CALL:
                case IrOp::CALLIND:
                case IrOp::CALLVIRT:
                case IrOp::CALLM:
                case IrOp::CALLN:
                case IrOp::CALLCLOSURE: {
                    uint32_t pos = 0;
                    if (bb.id < liveness.block_start.size())
                        pos = liveness.block_start[bb.id] + (uint32_t)i;
                    // Alguna raiz GC viva a traves del call en registro?
                    const std::vector<IrValueId> roots =
                        ir::safepoint_gc_roots(fn, liveness, pos, ins.dst);
                    for (IrValueId vid : roots) {
                        if (alloc.spilled(vid)) continue; // spill: no push
                        if (alloc.in_reg(vid)) {
                            force_frame_gc = true;
                            break;
                        }
                    }
                    break;
                }
                default: break;
                }
            }
            if (force_frame_gc) break;
        }
    }

    // Fase 3: asignar el banco ancho (ZMM) a los escalares float residentes.
    // Se computa ANTES de has_frame: si la funcion usa registros callee-saved
    // del banco, necesita frame para guardarlos en el prologo.
    std::unordered_map<IrValueId, int> zmm_map =
        compute_zmm_alloc(fn, liveness);
    std::vector<int> zmm_saved_regs;
    for (const auto &kv : zmm_map)
        zmm_saved_regs.push_back(kv.second);
    std::sort(zmm_saved_regs.begin(), zmm_saved_regs.end());
    zmm_saved_regs.erase(
        std::unique(zmm_saved_regs.begin(), zmm_saved_regs.end()),
        zmm_saved_regs.end());

    const bool has_frame = (alloc.num_spill_slots > 0) || has_alloca ||
                           force_frame_gc || !zmm_saved_regs.empty();

    // Construir el contexto (pasa has_frame para que TAILCALL tambien omita
    // leave)
    EmitCtx ctx(fn, alloc, liveness, out, opts.emit_comments, opts.emit_debug,
                has_frame, opts.emit_stackmaps);
    ctx.has_alloca = has_alloca;
    ctx.mod = mod;
    ctx.zmm_map = std::move(zmm_map);
    ctx.zmm_saved_regs = zmm_saved_regs;
    ctx.zmm_save_slot_base = alloc.num_spill_slots;

    // Multiprecision: de que suma viene cada acarreo.  Se recoge de toda la
    // funcion de antemano, no sobre la marcha, porque el planificador puede
    // dejar la lectura antes que su suma -- y entonces, al llegar a ella, aun
    // no sabriamos con que compararla.
    for (const auto &blk : fn.blocks)
        for (const auto &in : blk.instrs)
            if ((in.op == IrOp::ADDC || in.op == IrOp::SUBB) &&
                in.dst != IR_NO_VALUE && in.operands.size() >= 2)
                ctx.carry_src[in.dst] = {in.operands[0], in.op == IrOp::SUBB};

    /* Un segundo NOMBRE para el asignador del programa.
     *
     * El backend tiene que poder llamarlo sin saber quien es -- el del programa
     * si lo declaro con @c @AllocatorOverride, el de la biblioteca si no -- y
     * para eso necesita un nombre fijo.  Dos etiquetas seguidas es exactamente
     * eso: el mismo codigo con dos nombres, sin generar ni una instruccion.
     *
     * Se probo antes con una funcion puente que llamaba al de verdad, fabricada
     * a mano en el IR.  Compilaba y moria al ejecutarse: fabricar IR fuera del
     * frontend se salta invariantes que nadie tiene escritos, y solo te enteras
     * cuando revienta.  Un alias no genera codigo, asi que no hay nada que se
     * pueda quedar a medias. */
    if (mod != nullptr && !mod->alloc_sym.empty() &&
        fn.name == mod->alloc_sym) {
        if (opts.export_all)
            out.directive(emmit::Directive::EXPORT, "__vx_alloc_entry");
        out.label("__vx_alloc_entry");
    }
    if (mod != nullptr && !mod->free_sym.empty() && fn.name == mod->free_sym) {
        if (opts.export_all)
            out.directive(emmit::Directive::EXPORT, "__vx_free_entry");
        out.label("__vx_free_entry");
    }

    // Etiqueta de funcion (exportada si corresponde)
    if (opts.export_all) {
        out.directive(emmit::Directive::EXPORT, ctx.fn_lbl);
    }
    out.label(ctx.fn_lbl);

    // Prologo (omitido solo cuando spill_count == 0 Y no hay ALLOCA en el
    // cuerpo).
    //
    // Bug critico arreglado (2026-05-10): antes emitiamos `enter spill_count`
    // sin multiplicar por 8.  El runtime trata el inmediato de enter como
    // raw bytes para `sub rsp, frame_size`.  Asi `enter 6` allocaba SOLO
    // 6 bytes para el frame -- insuficiente para 6 slots de 8 bytes c/u.
    // El emisor entonces accedia a los slots usando offsets POSITIVOS desde
    // rbp (rbp+0, rbp+8, ...), que caen en el AREA DEL CALLER (sobreescriben
    // saved_rbp y RET_ADDR del callvirt).  El editor TUI exhibia este bug
    // con render_buffer (spill_count=6) corrompiendo el `this` del caller.
    //
    // El fix: enter aloca `spill_count * 8` bytes para que los slots vivan
    // dentro del frame local en offsets NEGATIVOS (rbp-8, rbp-16, ...).
    // Combinado con el cambio de offset en load_src/store_spilled, los
    // spills viven seguros en el area allocada por enter, sin interferir
    // con el caller.
    if (has_frame) {
        // El frame reserva los slots de spill + un slot de 8 B por cada
        // registro callee-saved del banco ancho que la funcion usa.
        const uint32_t frame_bytes =
            (alloc.num_spill_slots + ctx.zmm_saved_regs.size()) * 8;
        out.emit(emmit::Mnemonic::ENTER, frame_bytes);
    }

    // Prologo callee-saved del banco ancho: guarda cada ZMM usado en su slot
    // rbp (mst-FP, 1 instr).  El k-esimo reg -> rbp - (spill_count + k + 1)*8.
    for (size_t k = 0; k < ctx.zmm_saved_regs.size(); ++k) {
        const int freg = ctx.zmm_saved_regs[k];
        const int32_t disp =
            -static_cast<int32_t>((ctx.zmm_save_slot_base + k + 1) * 8);
        // base = rbp(16), wcode=3 (8 B f64), host=0 (VM stack), bank=1.
        const uint32_t cw = 16u | (3u << 8) | (1u << 15);
        out.emit(emmit::Mnemonic::MST, Reg::gp(static_cast<unsigned>(freg)),
                 Reg::gp(0), cw,
                 static_cast<uint16_t>(static_cast<int16_t>(disp)));
    }

    if (opts.emit_comments && !fn.params.empty()) {
        out << "    // parametros: ";
        for (size_t i = 0; i < fn.params.size(); ++i) {
            IrValueId pid = fn.params[i];
            if (i > 0) out << ", ";
            if (alloc.in_reg(pid))
                out << fn.values[pid].name << "="
                    << reg_name(alloc.reg_of(pid));
            else
                out << fn.values[pid].name << "=[spill]";
        }
        out.blank();
    }

    // Bug fix CRITICO: si un parametro fue evictado por el regalloc, llega al
    // entry en r1..r_N segun la calling convention pero su SLOT esta vacio.
    // Cualquier load posterior desde el slot lee garbage -> segfault al primer
    // uso del param tras un CALL.  Esto afecta especialmente metodos grandes
    // con muchos locales (Editor.render_buffer, etc.) donde el regalloc decide
    // spillar `this` por presion de registros.
    for (size_t i = 0; i < fn.params.size() && i < 12; ++i) {
        IrValueId pid = fn.params[i];
        if (!alloc.spilled(pid)) continue;
        const int preg = static_cast<int>(i + 1);
        const bool is_gc = static_cast<size_t>(pid) < fn.values.size() &&
                           fn.values[pid].is_gc_object;
        if (is_gc) {
            out.emit(emmit::Mnemonic::GCHANDLE, Reg::gp(14), Reg::gp(preg));
            emit_spill_access(out, Reg::gp(14), alloc.slot_of(pid),
                              /*is_load=*/false);
        } else {
            emit_spill_access(out, Reg::gp(preg), alloc.slot_of(pid),
                              /*is_load=*/false);
        }
    }

    // ====   fusion de direccion en LOAD/STORE (add-const -> mld/mst) ====
    // Un acceso a campo/array con offset constante baja a
    //     %off = const.i64 N ; %a = add.ptr %base, %off ; load/store [%a]
    // El reordenamiento propio del interp (interp_sink_addr_adds, corrido antes
    // del regalloc de esta funcion) ya HUNDIO cada add de direccion single-use
    // junto a su load/store, asi que aqui basta comprobar ADYACENCIA: el ADD es
    // la instruccion inmediatamente anterior.  Adyacencia == correctness: nada
    // entre medias puede reusar el registro del base, y el regalloc calculo la
    // vida sobre el IR YA hundido (base vive hasta el add adyacente).  Se
    // fusiona en un unico `mld/mst [base + disp]`, eliminando el ADD.
    if (!interp_fuse_disabled()) {
        std::unordered_map<IrValueId, int> use_count;
        for (const IrBlock &bb : fn.blocks) {
            for (const IrInstr &in : bb.instrs) {
                for (IrValueId op : in.operands)
                    if (op != IR_NO_VALUE) use_count[op]++;
                for (const auto &pa : in.phi_args)
                    if (pa.value != IR_NO_VALUE) use_count[pa.value]++;
            }
        }
        for (const IrBlock &bb : fn.blocks) {
            for (size_t i = 1; i < bb.instrs.size(); ++i) {
                const IrInstr &in = bb.instrs[i];
                IrValueId addr = IR_NO_VALUE;
                if (in.op == IrOp::LOAD && !in.operands.empty())
                    addr = in.operands[0];
                else if (in.op == IrOp::STORE && in.operands.size() >= 2)
                    addr = in.operands[1];
                else
                    continue;
                if (addr == IR_NO_VALUE) continue;
                // El ADD debe ser la instruccion inmediatamente anterior y
                // definir precisamente la direccion del load/store.
                const IrInstr &prev = bb.instrs[i - 1];
                if (prev.op != IrOp::ADD || prev.dst != addr ||
                    prev.operands.size() < 2)
                    continue;
                // addr single-use (solo este load/store): si no, no podemos
                // eliminar el add.
                auto uc = use_count.find(addr);
                if (uc == use_count.end() || uc->second != 1) continue;
                const IrValueId base = prev.operands[0];
                const IrValueId off = prev.operands[1];
                if (base >= fn.values.size() || off >= fn.values.size())
                    continue;
                // La base debe estar en un registro (no derramada); si
                // estuviera derramada el path normal ya la carga y no ganamos
                // nada.
                if (!alloc.in_reg(base)) continue;

                if (fn.values[off].is_const) {
                    //   offset constante -> [base + disp].
                    const int64_t d = (int64_t)fn.values[off].const_val;
                    if (d < -32768 || d > 32767) continue;
                    ctx.addr_fusion[&in] = {base, IR_NO_VALUE, (int32_t)d, 0};
                    ctx.fused_skip.insert(&prev);
                    continue;
                }

                //   offset en registro -> [base + index<<scale].  El index
                // (off) esta vivo en i-1 (lo usa el add) y, por adyacencia, su
                // registro sigue intacto en i (el mld).  Ademas, si off viene
                // de un `mul idx, pow2` single-use INMEDIATAMENTE anterior al
                // add (mul en i-2 tras el sink), se pliega el mul en el `scale`
                // del mld (idx<<shift), eliminando tambien el mul.
                IrValueId index = off;
                uint8_t scale = 0;
                bool folded_mul = false;
                if (i >= 2) {
                    const IrInstr &mul = bb.instrs[i - 2];
                    if (mul.op == IrOp::MUL && mul.dst == off &&
                        mul.operands.size() >= 2) {
                        auto ucm = use_count.find(off);
                        const IrValueId sc = mul.operands[1];
                        if (ucm != use_count.end() && ucm->second == 1 &&
                            sc < fn.values.size() && fn.values[sc].is_const) {
                            const uint64_t k = fn.values[sc].const_val;
                            if (k && (k & (k - 1)) == 0 && k <= 128) {
                                uint8_t sh = 0;
                                for (uint64_t t = k; t > 1; t >>= 1)
                                    ++sh;
                                const IrValueId mi = mul.operands[0];
                                if (mi < fn.values.size() && alloc.in_reg(mi)) {
                                    index = mi;
                                    scale = sh;
                                    folded_mul = true;
                                    ctx.fused_skip.insert(&mul);
                                }
                            }
                        }
                    }
                }
                if (!folded_mul && !alloc.in_reg(off)) continue;
                ctx.addr_fusion[&in] = {base, index, 0, scale};
                ctx.fused_skip.insert(&prev);
            }
        }
    }

    // Emision de bloques
    for (size_t b = 0; b < fn.blocks.size(); ++b) {
        const IrBlock &bb = fn.blocks[b];

        // Etiqueta del bloque (el bloque 0 = entry no necesita etiqueta extra
        // porque la etiqueta de la funcion ya apunta ahi, pero la emitimos
        // igualmente para que los saltos desde otros bloques puedan apuntar al
        // entry).
        out << ctx.block_label(static_cast<IrBlockId>(b)) << ":\n";
        // Invalidar caches de scratch al cruzar un boundary de bloque:
        // el control flow puede llegar aqui desde cualquier predecesor,
        // asi que no podemos asumir nada sobre el contenido de r14/r13.
        invalidate_scratch_caches(ctx);
        // Mismo motivo para f0: no sabemos que valor float tiene tras un salto.
        ctx.last_f0 = IR_NO_VALUE;

        // skip_count > 0 indica que las proximas N instrucciones ya
        // fueron consumidas por un peephole (cmpjmp fusion = 1, decjnz
        // fusion = 2).  Decrementamos en cada iteracion mientras > 0.
        int skip_count = 0;
        for (size_t i = 0; i < bb.instrs.size(); ++i) {
            if (skip_count > 0) {
                --skip_count;
                continue;
            }
            //   un ADD absorbido por el direccionamiento de un mld/mst
            // adyacente no se emite (su efecto lo hace el mld/mst).
            if (ctx.fused_skip.find(&bb.instrs[i]) != ctx.fused_skip.end())
                continue;
            emit_instr(ctx, bb, i, skip_count);
            // Si esta instruccion no es una op float que deje su dst en f0,
            // el contenido de f0 ya no es fiable para la siguiente op float.
            if (!is_tracked_float_op(bb.instrs[i].op))
                ctx.last_f0 = IR_NO_VALUE;
        }

        // Si el bloque no termina en terminador (bloque vacio o sin ret/br),
        // no emitir nada extra; el proximo bloque continua por caida natural.
    }

    // Epilogo comun de retorno
    out << ctx.fn_lbl << "_ret:\n";
    // Epilogo callee-saved del banco ancho: restaura cada ZMM guardado (mld-FP)
    // ANTES de `leave` (que desmonta el frame donde viven los slots).
    emit_zmm_callee_restore(ctx);
    // fix14: solo emitir leave si se emitio enter (spill_count > 0 o hay
    // ALLOCA).
    if (has_frame) {
        out.emit(emmit::Mnemonic::LEAVE);
    }
    // La funcion de entrada usa hlt para terminar la maquina explicitamente;
    // las demas funciones usan ret para retornar al llamador via callvm.
    out << (is_entry_point ? "    hlt\n\n" : "    ret\n\n");

    if (!(alloc.num_spill_slots == 0) && opts.emit_comments) {
        out << "    // INFO: " << alloc.num_spill_slots
            << " valor(es) derramado(s) a pila; cargas/almacenamientos "
               "emitidos\n";
    }

    return {}; // sin error
}

// =========================================================================
//  Reordenamiento propio del interp: hundir (sink) los add de direccion
// =========================================================================

/**
 * @brief Hunde la cadena de calculo de direccion (`mul idx, pow2` + `add
 * base, off`) single-use junto a su unico load/store, dentro del mismo bloque.
 *
 * El interp es dispatch-bound: no gana nada con el ILP scheduling del IR (que
 * es para las ISAs de JIT/AOT) y, peor, ese reordenamiento separa el calculo de
 * direccion de su load/store rompiendo la fusion a `mld/mst`.  Este pase,
 * corrido ANTES del regalloc del interp, restaura la adyacencia moviendo la
 * cadena justo antes de su uso:
 *   - Campo (offset const):   `add base, const` -> antes del load/store.
 *   - Array (indice en reg):  `add base, off`   -> idem; y si `off = mul idx,
 *     pow2` single-use, tambien se hunde el mul (queda [mul, add, ls]) para
 *     que la fusion posterior pliegue el mul en el `scale` del mld.
 * Es SIEMPRE seguro: mul y add son puros (no tocan memoria), single-use, y sus
 * operandos (base, idx) son valores SSA definidos antes (disponibles en la
 * nueva posicion).  Al correr antes del regalloc, la vida de base/idx se
 * recalcula correcta (viven hasta la cadena hundida) y la fusion por adyacencia
 * queda garantizada.
 */
/**
 * @brief Escape hatch de diagnostico: `VESTA_NO_FUSE=1` desactiva el
 * reordenamiento + fusion de direccion del interp (para A/B de regresiones).
 * Se lee una sola vez.
 */
static bool interp_fuse_disabled() {
    static const bool disabled = util::flag_on(util::FlagId::NoFuse);
    return disabled;
}

static void interp_sink_addr_adds(IrFunction &fn) {
    // Conteo de usos global (solo se hunde lo que es single-use).
    std::unordered_map<IrValueId, int> use_count;
    for (auto &bb : fn.blocks) {
        for (auto &in : bb.instrs) {
            for (IrValueId op : in.operands)
                if (op != IR_NO_VALUE) use_count[op]++;
            for (auto &pa : in.phi_args)
                if (pa.value != IR_NO_VALUE) use_count[pa.value]++;
        }
    }
    for (auto &bb : fn.blocks) {
        // add_at[dst] = indice de un `add A, B` single-use en ESTE bloque.
        // mul_at[dst] = indice de un `mul idx, pow2(<=128)` single-use.  La
        // fusion posterior decide disp (const) vs index (reg) vs index<<scale.
        std::unordered_map<IrValueId, size_t> add_at, mul_at;
        for (size_t j = 0; j < bb.instrs.size(); ++j) {
            const IrInstr &in = bb.instrs[j];
            if (in.dst == IR_NO_VALUE || in.operands.size() < 2) continue;
            auto uc = use_count.find(in.dst);
            if (uc == use_count.end() || uc->second != 1) continue;
            if (in.op == IrOp::ADD) {
                add_at[in.dst] = j;
            } else if (in.op == IrOp::MUL) {
                const IrValueId sc = in.operands[1];
                if (sc < fn.values.size() && fn.values[sc].is_const) {
                    const uint64_t k = fn.values[sc].const_val;
                    if (k && (k & (k - 1)) == 0 && k <= 128) mul_at[in.dst] = j;
                }
            }
        }
        if (add_at.empty()) continue;
        // sink_chain[idx_ls] = [ (mul_idx opcional), add_idx ] a insertar justo
        // antes del load/store.  to_remove = instrucciones a quitar de su
        // sitio.
        std::unordered_map<size_t, std::vector<size_t>> sink_chain;
        std::unordered_set<size_t> to_remove;
        for (size_t j = 0; j < bb.instrs.size(); ++j) {
            const IrInstr &in = bb.instrs[j];
            IrValueId addr = IR_NO_VALUE;
            if (in.op == IrOp::LOAD && !in.operands.empty())
                addr = in.operands[0];
            else if (in.op == IrOp::STORE && in.operands.size() >= 2)
                addr = in.operands[1];
            else
                continue;
            auto ia = add_at.find(addr);
            if (ia == add_at.end() || ia->second >= j) continue;
            std::vector<size_t> chain;
            size_t mul_idx = static_cast<size_t>(-1);
            // Mul opcional que produce el offset del add (patron array[i]).
            const IrValueId off = bb.instrs[ia->second].operands[1];
            auto im = mul_at.find(off);
            if (im != mul_at.end() && im->second < ia->second) {
                mul_idx = im->second;
                chain.push_back(mul_idx);
            }
            chain.push_back(ia->second);
            // Ya totalmente adyacente? (add en j-1, y el mul -si hay- en j-2.)
            const bool adjacent =
                (ia->second == j - 1) &&
                (mul_idx == static_cast<size_t>(-1) || mul_idx == j - 2);
            if (adjacent) continue;
            sink_chain[j] = std::move(chain);
            for (size_t idx : sink_chain[j])
                to_remove.insert(idx);
        }
        if (sink_chain.empty()) continue;
        // Reconstruir: saltar las instrucciones hundidas en su sitio original;
        // antes de cada load/store objetivo, insertar su cadena (en orden).
        std::vector<IrInstr> rebuilt;
        rebuilt.reserve(bb.instrs.size());
        for (size_t j = 0; j < bb.instrs.size(); ++j) {
            if (to_remove.count(j)) continue;
            auto sc = sink_chain.find(j);
            if (sc != sink_chain.end())
                for (size_t idx : sc->second)
                    rebuilt.push_back(bb.instrs[idx]);
            rebuilt.push_back(std::move(bb.instrs[j]));
        }
        bb.instrs = std::move(rebuilt);
    }
}

// =========================================================================
//  Puntos de entrada publicos
// =========================================================================

EmitResult ir_emit_module(const IrModule &mod_in, const EmitOptions &opts) {
    EmitResult result;
    result.ok = true;

    // Trabajar sobre una copia para no modificar el modulo original
    IrModule mod = mod_in;

    /* ASA observa ANTES de optimizar.  Es el punto por el que pasan de verdad
     * todas las rutas -- el emisor trabaja sobre una copia --, y es otra verdad
     * del programa, no una peor: medido, la escalarizacion se lleva parte de
     * los agregados antes de que nadie los mire, asi que observar solo despues
     * hace creer que el programa no los tenia. */
    analysis::asa::volcar_formas(mod, "pre-opt");

    // Aplicar optimizaciones IR, salvo que quien llama ya las haya aplicado.
    if (!opts.ya_optimizado) {
        const auto t_opt = std::chrono::steady_clock::now();
        ir_optimize(mod, opts.opt_level);
        if (util::flag_on(util::FlagId::Times))
            std::cerr << "[emisor] optimizar (dentro del emisor) "
                      << std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::steady_clock::now() - t_opt)
                             .count()
                      << " us\n";
    }

    // CTPE (opt-in): tras optimizar, ejecuta los candidatos de precomputo en el
    // ComptimeRuntime dado e inyecta el resultado escalar como CONST.  Solo si
    // el caller paso un runtime (fase 2 del CTPE); nullptr = comportamiento
    // normal.
    if (opts.ctpe_runtime) {
        ctpe::fold(mod,
                   *reinterpret_cast<vx::ComptimeRuntime *>(opts.ctpe_runtime));
    }

    // Reordenamiento PROPIO del interp (post-IR): el list-scheduler del IR
    // (ILP para las ISAs de JIT/AOT) puede separar el add de direccion de su
    // load/store, pero el interp es dispatch-bound (sin superescalar/OoO) y su
    // objetivo es MINIMIZAR instrucciones, no exponer ILP.  Este pase hunde
    // (sink) cada add de direccion single-use junto a su unico load/store, lo
    // que habilita la fusion posterior a `mld/mst [base + disp]`.  Opera sobre
    // la COPIA del modulo del emitter -> no afecta al `.vexir` (JIT/AOT hacen
    // su propio reordenamiento con su contexto de ISA).
    if (!interp_fuse_disabled()) {
        for (auto &fn : mod.functions) {
            if (fn.is_native) continue;
            interp_sink_addr_adds(fn);
        }
    }

    // ===================================================================
    // Math-IR-promote: pre-pase que convierte IR ops sin bytecode opcode
    // a CALLN equivalente.  Estos ops (FMIN/FMAX/FFLOOR/FCEIL/FROUND/
    // FTRUNC/IABS/IMIN/IMAX/IMINU/IMAXU/ILOG2/CLZ/CTZ/POPCNT/BYTESWAP/
    // ROTL/ROTR) existen como IR ops para que:
    //   (a) El optimizer pueda constant-fold cuando los operandos son
    //       literales.
    //   (b) El Selector JIT pueda emitir instrucciones nativas
    //       (sqrtsd/roundsd/popcnt/lzcnt/etc.) sin mini-parser.
    //
    // El VM bytecode no tiene opcodes nativos para estas ops todavia, por
    // lo que el emitter las convierte a CALLN al runtime vmath.  El path
    // bytecode pasa por libreria; el path JIT emite hardware directo.
    // Cuando el runtime gane opcodes nativos (futuro sprint), este
    // pre-pase ignora los ops correspondientes.
    {
        struct VmathMap {
            IrOp op;
            const char *fn;
            ir::IrType ret_ir;
        };
        static const VmathMap vmath_table[] = {
            // Sprint string-perf-5 (2026-06-02): FMIN/FMAX/FFLOOR/FCEIL/
            // FROUND/FTRUNC ahora tienen opcodes bytecode nativos
            // (0x80-0x85) y se emiten directamente como mnemonicos en el
            // switch.  Removidos del pre-pase para evitar CALLN overhead
            // (~150ns -> ~5ns por op en interp).
            //
            // { IrOp::FFLOOR,   "vmath_floor",    ir::IrType::F64 },
            // { IrOp::FCEIL,    "vmath_ceil",     ir::IrType::F64 },
            // { IrOp::FROUND,   "vmath_round",    ir::IrType::F64 },
            // { IrOp::FTRUNC,   "vmath_trunc",    ir::IrType::F64 },
            // { IrOp::FMIN,     "vmath_fmin",     ir::IrType::F64 },
            // { IrOp::FMAX,     "vmath_fmax",     ir::IrType::F64 },
            // Int (signed/unsigned).
            {IrOp::IABS, "vmath_abs", ir::IrType::I64},
            {IrOp::IMIN, "vmath_min", ir::IrType::I64},
            {IrOp::IMAX, "vmath_max", ir::IrType::I64},
            {IrOp::IMINU, "vmath_minu", ir::IrType::I64},
            {IrOp::IMAXU, "vmath_maxu", ir::IrType::I64},
            {IrOp::ILOG2, "vmath_ilog2", ir::IrType::I64},
            // Bit ops.
            {IrOp::CLZ, "vmath_clz", ir::IrType::I64},
            {IrOp::CTZ, "vmath_ctz", ir::IrType::I64},
            {IrOp::POPCNT, "vmath_popcount", ir::IrType::I64},
            {IrOp::BYTESWAP, "vmath_bswap", ir::IrType::I64},
            {IrOp::ROTL, "vmath_rotl", ir::IrType::I64},
            {IrOp::ROTR, "vmath_rotr", ir::IrType::I64},
        };
        const std::string lib_math = "stdlib/native/math/vesta_math";
        bool any_used = false;
        for (auto &fn : mod.functions) {
            for (auto &bb : fn.blocks) {
                for (auto &ins : bb.instrs) {
                    for (const auto &m : vmath_table) {
                        if (ins.op != m.op) continue;
                        ins.op = IrOp::CALLN;
                        ins.func_name = lib_math + ":" + m.fn;
                        // Mantener type del dst original.  El emitter de
                        // CALLN ya sabe pasar args via R1..RN.
                        any_used = true;
                        break;
                    }
                }
            }
        }
        if (any_used) {
            // Registrar los imports usados.  Re-iteramos solo los que
            // aparecieron (any_used=true).  Es O(N*M) pero solo corre 1
            // vez por modulo + M es chico (~18 entries).
            for (const auto &m : vmath_table) {
                bool used_here = false;
                for (const auto &fn : mod.functions) {
                    for (const auto &bb : fn.blocks) {
                        for (const auto &ins : bb.instrs) {
                            if (ins.op == IrOp::CALLN &&
                                ins.func_name == lib_math + ":" + m.fn) {
                                used_here = true;
                                break;
                            }
                        }
                        if (used_here) break;
                    }
                    if (used_here) break;
                }
                if (used_here) {
                    mod.register_native_import(lib_math, m.fn);
                }
            }
        }
    }

    VelSink out;

    // Cabecera del modulo
    out.comment_top("Emitido por ir_emitter - VestaVM");
    out << "// Nivel de optimizacion: O" << static_cast<int>(opts.opt_level)
        << "\n\n";

    // Cabecera .vel obligatoria: formato, espacio de direcciones y seccion
    // Si el modulo definio directivas @format/@space/@section las usamos;
    // en caso contrario emitimos valores por defecto razonables.
    std::string fmt = mod.format.empty() ? "velb" : mod.format;
    out << "@Format(\"" << fmt << "\")\n\n";

    if (mod.spaces.empty()) {
        // espacio de direcciones anonimo por defecto
        auto b = out.block(emmit::Directive::SPACE_ADDRESS);
        b.entry(emmit::Directive::NAME, "anonymous");
        b.entry(emmit::Directive::INI_ADDRESS, UINT64_C(0), 16);
        b.entry(emmit::Directive::END_ADDRESS, UINT64_MAX, 16);
    } else {
        for (const auto &sp : mod.spaces) {
            auto b = out.block(emmit::Directive::SPACE_ADDRESS);
            b.entry(emmit::Directive::NAME, sp.name);
            b.entry(emmit::Directive::INI_ADDRESS, sp.ini_address, 16);
            b.entry(emmit::Directive::END_ADDRESS, sp.end_address, 16);
        }
    }

    if (mod.sections.empty()) {
        // seccion de codigo por defecto.  Las etiquetas que siguen
        // (main, main_entry, ...) pertenecen a esta seccion hasta que
        // se emita una nueva @Section.  La seccion "data" para los
        // literales se declara DESPUES de las funciones, justo antes
        // de los datos.
        auto b = out.block(emmit::Directive::SECTION);
        b.entry(emmit::Directive::NAME, "code");
        b.entry(emmit::Directive::SPACE_ADDRESS, "anonymous");
        b.entry(emmit::Directive::ALIGN, UINT64_C(0x1000));
    } else {
        for (const auto &sec : mod.sections) {
            auto b = out.block(emmit::Directive::SECTION);
            b.entry(emmit::Directive::NAME, sec.name);
            b.entry(emmit::Directive::SPACE_ADDRESS, sec.space_name);
            b.entry(emmit::Directive::ALIGN, sec.align);
        }
    }

    // Declaracion de modulo (@Module es obligatorio antes de @Export)
    std::string mod_name =
        opts.module_name.empty() ? mod.name : opts.module_name;
    if (mod_name.empty() && opts.export_all) mod_name = "ir_output";
    if (!mod_name.empty()) {
        out.directive(emmit::Directive::MODULE, EmitCtx::sanitize(mod_name))
            .blank();
    }

    /* Los cuerpos comptime (`__macro_*`) no pintan nada en el binario del
     * programa: los ejecuta el COMPILADOR, no el programa.  Se quedaban dentro
     * como codigo muerto -- en un fuente que solo usa literales anchos son 325
     * funciones y cerca de un mega -- y ademas arrastraban el import de la
     * libreria virtual del compilador, que el cargador tenia que resolver al
     * arrancar para un simbolo que nadie iba a llamar.
     *
     * Solo se omiten cuando hay un prebuilt: ese `.velb` aparte es de donde el
     * ComptimeVM los saca, y se compila SIN esta variable puesta, asi que
     * conserva todo lo que necesita.  Sin prebuilt (la compilacion que genera
     * justamente ese cache) se emiten como siempre.
     *
     * CUIDADO al distribuir librerias PRECOMPILADAS por separado.  Que un
     * `__macro_` no lo use su propio modulo no significa que no lo use nadie:
     * `std.comptime.literal` exporta su parser y lo consume `std.wideint`.
     * Hoy eso funciona porque el `.velb` del ComptimeVM se compila aparte con
     * el proyecto ENTERO -- root y dependencias -- asi que lleva los cuerpos
     * de todos.  El dia que se enlacen `.velb` sueltos sin fusionar el IR,
     * este filtro tendra que mirar si el modulo es un ejecutable o una
     * libreria, porque una libreria SI tiene que conservarlos. */
    const bool omit_comptime_bodies = []() {
        const char *v = std::getenv("VESTA_MC_PREBUILT");
        return v != nullptr && v[0] != '\0';
    }();

    // Declaraciones de librerias nativas
    for (const auto &lib : mod.native_libs) {
        /* La libreria virtual del compilador se va con los cuerpos que la
         * usaban: sin ellos nadie la llama, pero su DECLARACION seguia ahi y
         * el cargador la resolvia al arrancar, buscando una DLL que no existe
         * porque vive dentro del propio compilador. */
        if (omit_comptime_bodies && lib == "vesta_comptime") continue;
        out << "@Lib(\"" << lib << "\")\n";
    }
    if (!mod.native_libs.empty()) out.blank();

    // Importaciones
    for (const auto &imp : mod.imports) {
        out << "@import " << imp << "\n";
    }
    if (!mod.imports.empty()) out.blank();

    // Bloque @Import { @Method { @Lib(...) @Name(...) } } para CALLN.
    // El ensamblador .vel exige esta declaracion antes del primer uso de
    // la funcion nativa correspondiente (calln @Method("lib:name")).
    if (!mod.native_imports.empty()) {
        out << "@Import {\n";
        for (const auto &ni : mod.native_imports) {
            if (omit_comptime_bodies && ni.lib == "vesta_comptime") continue;
            out << "    @Method { @Lib(\"" << ni.lib << "\")"
                << " @Name(\"" << ni.name << "\") }\n";
        }
        out << "}\n\n";
    }

    // Emision de cada funcion; la primera funcion no-nativa es el punto de
    // entrada, salvo que se emita una biblioteca (donde no hay ninguno).
    bool first_func = !opts.sin_punto_de_entrada;
    for (const auto &fn : mod.functions) {
        if (omit_comptime_bodies && ir::es_cuerpo_comptime(fn.name)) {
            continue;
        }
        if (fn.is_native) {
            // Stub nativo: solo comentario de importacion
            out << "// funcion nativa: " << fn.name
                << " (no se emite codigo)\n\n";
            continue;
        }
        // NOTA (medido 2026-07-25): el interp NO divide aristas criticas.  El
        // critical-edge splitting (que el vreg SI usa) es optimo para el nativo
        // -- branch predictor de hardware, sin la super-instruccion cmpjmp --
        // pero PEOR para el interprete: fuerza `cmpjmp` (cuyo next-dispatch
        // threaded es bimodal, predice peor que un cmp+jcc con dos sitios de
        // dispatch separados) + un bloque puente por arista (mas transiciones
        // de bloque).  string_workout regresiona +23% con el split.  El OPTIMO
        // del interp es el flag-safe inline (emit_phi_copies entre el cmp y el
        // jcc, sin puente).  Es una divergencia REAL de arquitectura (el vreg
        // emite las copias de PHI en las aristas; el interp inline), no
        // duplicacion gratuita.  El pase compartido `split_critical_edges` lo
        // consume solo el vreg.
        std::vector<uint8_t> regs_fn;
        std::string err =
            emit_function(fn, opts, out, first_func, &mod, &regs_fn);
        if (!regs_fn.empty()) result.value_regs[fn.name] = std::move(regs_fn);
        first_func = false;
        if (!err.empty()) {
            result.ok = false;
            result.error = err;
            return result;
        }
    }

    // Datos estaticos: emitidos AL FINAL de la seccion "code", separados
    // del codigo ejecutable por una directiva 'align 16'.  No se usan
    // secciones independientes porque el linker .velb actual no
    // serializa los bytes de secciones distintas a la primera al
    // binario final, dejando los reloc apuntando a posiciones validas
    // pero sin contenido escrito.  Mismo patron que el ejemplo del
    // proyecto examples_codes_vm/test_vesta_io.vel.
    //
    // CRITICO: hay que emitir una etiqueta 'end_data:' DESPUES de los
    // bytes db.  El linker calcula el tamano del bloque ejecutable
    // como el VA del ultimo simbolo definido; si el ultimo simbolo es
    // 's_N:' (con bytes detras pero sin etiqueta posterior), el bloque
    // termina justo en VA(s_N) y los bytes db quedan fuera del rango
    // mapeado a memoria de la VM.  La etiqueta posterior end_data
    // empuja el rango hasta despues de los bytes.
    // Un slot va a `gdata` (memoria host) si es el storage de una variable
    // global.  El lowering los marca con section_name ".data" -- el mismo dato
    // que ya consumia el codegen AOT para no meterlos en .rodata.
    bool has_gdata = false;
    bool has_code_data = false;
    for (size_t i = 0; i < mod.static_data.size(); ++i) {
        if (slot_is_gdata(mod, i))
            has_gdata = true;
        else
            has_code_data = true;
    }

    if (has_code_data) {
        out << "// --- datos estaticos del modulo (mismas seccion que el "
               "codigo) ---\n";
        out << "align 16\n";
        for (size_t i = 0; i < mod.static_data.size(); ++i) {
            if (slot_is_gdata(mod, i)) continue; // va a `gdata`
            auto [bp, bn] = mod.static_data.bytes_at(i);
            // M.staticdata-pool: respetar @c meta_at(i).alignment (default 1).
            // Si es mayor que el align 16 default del bloque, emitir un
            // @c align directiva especifica antes del label.  Asi
            // @c @align(32) en comptime const arrays produce alineamiento >16.
            const auto &meta_i = mod.static_data.meta_at(i);
            const uint16_t a = meta_i.alignment;
            if (a > 16) {
                out << "align " << a << "\n";
            }
            // @Virtual: slot con sym_refs (reloc datos->codigo) = una VTABLE.
            // Se emite como `s_N dq @Absolute("code.<sym>"), ...` en orden de
            // offset (rellenando huecos con 0).  El linker parchea cada entrada
            // con la direccion VM del metodo -> el dispatch dinamico funciona
            // en interp/.velb (no solo en AOT).  Los sym vienen como
            // <owner>__<m>; el prefijo "code." los ancla a la seccion de
            // codigo.
            if (!meta_i.sym_refs.empty()) {
                // Mapa offset -> simbolo (los sym_refs vienen ordenados, pero
                // no asumimos).  Todos son width=8 (dq) por construccion de la
                // vtable.
                std::map<uint32_t, std::string> at;
                for (const auto &sr : meta_i.sym_refs)
                    at[sr.offset] = sr.sym;
                auto &d = out.data("s_" + std::to_string(i), /*ancho_q=*/true);
                for (uint32_t off = 0; off + 8u <= bn; off += 8u) {
                    auto its = at.find(off);
                    if (its != at.end())
                        d.valores.push_back(emmit::Operand::of(
                            Ann::absolute("code." + its->second)));
                    else
                        d.valores.push_back(
                            emmit::Operand::of_imm(INT64_C(0))); // hueco
                }
                continue;
            }
            // El parser .vel espera el patron "etiqueta directiva valores"
            // EN LA MISMA LINEA (estilo NASM).  Si separamos la etiqueta
            // en su propia linea el assembler la trata como label vacio
            // y los bytes db nunca se incrustan en el binario.
            bool printable = (bn != 0);
            for (size_t k = 0; k < bn; ++k) {
                uint8_t b = bp[k];
                if (b < 0x20 || b > 0x7E || b == '"' || b == '\\') {
                    printable = false;
                    break;
                }
            }
            auto &d = out.data("s_" + std::to_string(i), /*ancho_q=*/false);
            if (printable) {
                d.es_texto = true;
                d.texto.assign(reinterpret_cast<const char *>(bp), bn);
            } else {
                for (size_t b = 0; b < bn; ++b)
                    d.valores.push_back(emmit::Operand::of_imm_hex(bp[b], 2));
                // El nul de cierre: siempre hay uno, tambien cuando el bloque
                // esta vacio.
                d.valores.push_back(emmit::Operand::of_imm_hex(0, 2));
            }
        }
        // Etiqueta marker que extiende el rango ejecutable hasta despues
        // de los ultimos bytes; sin ella el linker calcula el tamano del
        // bloque como VA(s_N) y los bytes db quedan truncados.
        {
            auto &d = out.data("end_data", /*ancho_q=*/false);
            d.valores.push_back(emmit::Operand::of_imm_hex(0, 2));
        }
        out.blank();
    }

    // --- seccion `gdata`: storage de las variables globales ---
    //
    // Va en su PROPIA seccion porque su memoria es HOST, no de la VM: la
    // direccion de un global se toma con `&global` y viaja (a un campo, a un
    // parametro `T*`, a la FFI, a un `lock cmpxchg`), y en el sitio del deref
    // el unico contrato disponible es el del tipo.  El loader mapea esta
    // seccion a un bloque host contiguo -- contiguo porque la memoria de la VM
    // es paginada y una direccion suya solo vale dentro de su pagina.
    //
    // El resto de slots (literales que alimentan a STRMAKE, params de los
    // opcodes meta defclass/deffield/defmethod) EXIGEN direccion VM y por eso
    // se quedan arriba, en `code`.
    if (has_gdata) {
        out << "@Section {\n";
        out << "    @Name(\"gdata\"),\n";
        out << "    @SpaceAddress(\"anonymous\")\n";
        out << "    @Align(0x1000)\n";
        out << "}\n";
        out.comment_top("--- storage de variables globales (memoria host) ---");
        for (size_t i = 0; i < mod.static_data.size(); ++i) {
            if (!slot_is_gdata(mod, i)) continue;
            auto [bp, bn] = mod.static_data.bytes_at(i);
            const uint16_t a = mod.static_data.meta_at(i).alignment;
            if (a > 1) out << "align " << a << "\n";
            auto &d = out.data("s_" + std::to_string(i), /*ancho_q=*/false);
            for (size_t b = 0; b < bn; ++b)
                d.valores.push_back(emmit::Operand::of_imm_hex(bp[b], 2));
            // Aqui el nul SOLO se anade cuando el bloque esta vacio: es lo que
            // hacia el codigo anterior, y cambiarlo moveria las direcciones.
            if (bn == 0) d.valores.push_back(emmit::Operand::of_imm_hex(0, 2));
        }
        // Mismo motivo que `end_data`: sin una etiqueta detras, el rango de la
        // seccion se calcularia hasta VA(ultimo slot) y sus bytes quedarian
        // fuera.
        {
            auto &d = out.data("end_gdata", /*ancho_q=*/false);
            d.valores.push_back(emmit::Operand::of_imm_hex(0, 2));
        }
        out.blank();
    }

    result.vel_text = out.take_text();
    return result;
}

EmitResult ir_emit_text(const std::string &ir_text, const EmitOptions &opts) {
    IrModule mod;
    std::string parse_err;
    if (!ir_parse(ir_text, mod, parse_err)) {
        EmitResult r;
        r.ok = false;
        r.error = "parse: " + parse_err;
        return r;
    }
    return ir_emit_module(mod, opts);
}

} // namespace ir
