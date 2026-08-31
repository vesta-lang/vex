/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/regalloc_rewrite.cpp
 * @brief Implementacion del rewrite vreg -> fisico ( D.7, commit 4a).
 *        Ver regalloc_rewrite.h y doc/REGALLOC.md.
 */

#include "util/env_flags.h"
#include "jit/asm_deferred.h"
#include "jit/frame_addr.h"
#include "jit/frame_emit.h"
#include "jit/regalloc_rewrite.h"

#include "codegen/transition_planner.h" // que movimientos exige cada punto del programa
#include "codegen/parallel_move.h" // sequence_parallel_moves (compartido 3 modos)

#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility> // std::pair (marshal stack-args; UCRT64 no transitivo)
#include <vector>

#include "jit/osr_registry.h" // registro de bucles re-entrables
#include "vesta_rt/abi.h" // VESTA_PROC_OSR_BUFFER_OFFSET / VESTA_OSR_BUFFER_N
#include "vx/asm/asm_backend.h"  // ensamblar el asm DIFERIDO post-RA
#include "vx/asm/asm_phys_reg.h" // nombre del reg fisico ($N -> reg)
#include <cctype>

namespace jit {

namespace {

/** @brief Diagnostico/A-B: VESTA_JIT_NO_FRAMELESS=1 fuerza el frame
 *  completo (push rbp / mov rbp,rsp / pop rbp) incluso en hojas que
 *  calificarian para frameless.  Sirve para medir el efecto del
 *  frameless o aislar un posible bug del codegen del prologo/epilogo
 *  (el codegen mas safety-critical: un fallo aqui corrompe el heap via
 *  el precise stack-scan de la GC). */
bool jit_no_frameless() noexcept {
    static const bool off = util::flag_on(util::FlagId::JitNoFrameless);
    return off;
}

/** @brief True si la ALU binaria @p op es conmutativa. */
bool is_commutative(MOp op) noexcept {
    switch (op) {
    case MOp::ADD:
    case MOp::AND:
    case MOp::OR:
    case MOp::XOR:
    case MOp::IMUL: return true;
    default: return false;
    }
}

/** @brief True si @p op es una ALU binaria que reescribimos (4a). */
bool is_bin_alu(MOp op) noexcept {
    switch (op) {
    case MOp::ADD:
    case MOp::SUB:
    case MOp::AND:
    case MOp::OR:
    case MOp::XOR:
    case MOp::IMUL: return true;
    default: return false;
    }
}

/**
 * @struct AllocationResolver
 * @brief El punto de entrada del Rewrite a las ubicaciones.  Es la funcion
 *
 *     (valor, momento)  ->  ValueLocation
 *
 * OCULTA por completo: el timeline, los segmentos, la busqueda por posicion y
 * la convencion temporal (use_point/def_point).  Quien lo usa (el Lowerer) NO
 * sabe COMO se resuelve una ubicacion: pregunta @c resolve_use(vid) / @c
 * resolve_def(vid) -- el verbo es RESOLVER (una CONSULTA, no "devolver el
 * uso").  Extraido del Lowerer para no engordarlo; es su punto natural de
 * crecimiento cuando lleguen remat/split (mas momentos, mas tipos de ubicacion)
 * sin que el Rewrite se entere.
 */
struct AllocationResolver {
    const codegen::AllocationTimeline *timeline = nullptr;
    uint32_t cur_gi =
        0; ///< instr actual; resolve_use/def preguntan use/def_point(cur_gi).

    codegen::ValueLocation resolve_at(uint32_t vid,
                                      codegen::LinearPos pos) const noexcept {
        return timeline->lookup(vid, pos);
    }
    codegen::ValueLocation resolve_use(uint32_t vid) const noexcept {
        return resolve_at(vid, codegen::use_point(cur_gi));
    }
    codegen::ValueLocation resolve_def(uint32_t vid) const noexcept {
        return resolve_at(vid, codegen::def_point(cur_gi));
    }
};

/**
 * @struct Lowerer
 * @brief Estado del rewrite de una funcion.
 */
struct Lowerer {
    const codegen::AllocationResult
        &ar; ///< frame + timeline (lo que consume el Rewrite)
    AllocationResolver
        resolver; ///< "¿donde vive un vreg?" (delega en el timeline)
    const TargetRegInfo &tri;
    bool vm_abi = false;   ///< VM_ABI (salva RBX=ProcessVM*) vs host leaf
    bool no_frame = false; ///< hoja frameless: sin push/mov rbp ni sub rsp
    bool naked = false;    ///<  NR @Naked: sin prologo/epilogo/ret
    bool fpo = false;      ///< frame-pointer omission: liga rbp/rsp a un param
    int32_t frame_below = 0;  ///< FPO: [rbp+off] -> [rsp + frame_below + off]
    uint32_t k = 0;           ///< numero de callee-saved asignados
    uint32_t total_saved = 0; ///< callee-saved + (vm_abi ? 1 (rbx) : 0)
    int32_t spill_bytes = 0;  ///< tamano del area de spills (alineado)
    /// Args ilimitados (JIT/AOT): numero de slots GP que se pasan por PILA
    /// (overflow de los arg_regs).  Se reservan en el FONDO del frame
    /// (encima del shadow Win64) y se direccionan RSP-relativo en el call.
    /// El interprete tiene limite 12 (bytecode), el JIT/AOT no.
    uint32_t out_stack_args = 0;
    /// Offset RSP del primer stack-arg: 32 (Win64 shadow) o 0 (SysV).
    int32_t stack_arg_base = 0;
    /// Tamano de PALABRA del target: lo que ocupa cada argumento pasado por
    /// pila.  Se deduce del ABI igual que @c stack_arg_base -- tres registros
    /// de argumento es regparm(3), o sea x86-32 -- para que siga siendo
    /// correcto compilando para otra arquitectura que la del host.  Con el 8
    /// fijo de 64 bits, en 32 los argumentos que no caben en registro salian
    /// espaciados el doble de lo que el callee espera.
    int32_t word_bytes() const {
        return tri.arg_regs[static_cast<size_t>(RegClass::GP)].size() == 3 ? 4
                                                                           : 8;
    }
    /// Commit 8: offset (desde RBP) del inicio del area de allocas
    /// (justo debajo de los spill slots) + cursor de asignacion.
    uint32_t alloca_base = 0;
    uint32_t alloca_cursor = 0;
    /// Fase 2 (ALLOCA_VM): la fn reserva en el VM stack del proceso.
    /// Hay que salvar el VM-RSP (proc->stack_pointer) al entry y
    /// restaurarlo en CADA RET, o el VM stack hace leak/overflow entre
    /// llamadas.  @c vm_rsp_save_off es el offset (negativo desde RBP)
    /// del slot que guarda el VM-RSP original (un qword debajo del area
    /// de allocas host, por encima del shadow space Win64).
    bool has_vm_alloca = false;
    int32_t vm_rsp_save_off = 0;
    /// Callback-ABI save-set (jubilacion de slots): si @c cb_save_regs, el
    /// frame reserva 128B (16 qwords) donde @c CB_SAVE_REGS salva
    /// proc->registers[0..15] del caller VM.  @c cb_save_base_off es el offset
    /// (negativo desde RBP) del slot del reg 0; el reg r vive en
    /// @c cb_save_base_off - r*8.
    bool cb_save_regs = false;
    int32_t cb_save_base_off = 0;
    MReg scr0_ = MReg::R10;
    MReg scr1_ = MReg::R11;
    /* Los temporales enteros estan APARTADOS: no se le ofrecen al asignador en
     * ninguna funcion, la necesite o no.  Eso parecia una reserva a ciegas que
     * habia que quitar -- dos registros menos para todas a cambio de las que si
     * los usan -- y estaba anotado como trabajo pendiente.
     *
     * MEDIDO (2026-08-06, instrumentando estos accesos sobre el corpus): los
     * usa el 86-88% de las funciones compiladas por el AOT y el 100% de las que
     * el JIT considera calientes.  O sea que la reserva NO es el problema:
     * devolverlos al reparto le daria dos registros al ~13% restante, que son
     * funciones pequenas que ni derraman.  Se deja como esta, y esto queda
     * escrito para no volver a abrir la pregunta.
     *
     * Lo del banco ancho era distinto y por eso si se hizo: alli hay un
     * predicado barato y ANTERIOR a asignar -- "la funcion no toca ningun
     * flotante" -- que en la mayoria de las funciones es cierto.  El entero no
     * tiene equivalente porque el temporal hace falta justo cuando se derrama,
     * y eso no se sabe hasta despues.
     *
     * Todo acceso pasa por @c scr0() y compania: un solo sitio por donde mirar
     * el dia que el asignador sepa entregar temporales. */
    /// FP-regalloc ( AOT C1 float): scratch XMM del rewrite
    /// (materializar spills FP + two-address legalization de ADDSD/etc),
    /// analogo a scr0()/scr1() GP.  Por defecto XMM14/XMM15 (ver
    /// @c target_x86_64_target); se sobreescriben desde @c tri.scratch[FP].
    MReg fscr0_ = MReg::XMM14;
    MReg fscr1_ = MReg::XMM15;

    /** @brief Primer temporal entero. */
    MReg scr0() const noexcept { return scr0_; }
    /** @brief Segundo temporal entero. */
    MReg scr1() const noexcept { return scr1_; }
    /** @brief Primer temporal del banco ancho. */
    MReg fscr0() const noexcept { return fscr0_; }
    /** @brief Segundo temporal del banco ancho. */
    MReg fscr1() const noexcept { return fscr1_; }
    /// Tamano de un slot de pila / push (= pointer_size del target):
    /// 8 en x86-64, 4 en x86-32.  El frame (callee-saved, spill slots,
    /// epilogue lea) se mide en estos slots; usar 8 fijo en x86-32
    /// desalineaba el `lea esp,[ebp-N]` -> el ret leia basura.
    uint32_t SZ = 8;
    /// MFunction destino: necesario para crear labels intra-expansion
    /// (LOAD_VM/STORE_VM page-cache) via @c pf->new_label().  Se asigna
    /// en @c rewrite_to_physical tras construir pf.
    MFunction *pf = nullptr;

    Lowerer(const codegen::AllocationResult &a, const TargetRegInfo &t,
            AbiKind abi, bool has_calls, uint32_t alloca_total,
            bool has_vm_alloca_in, uint32_t out_stack_args_in = 0,
            bool has_stack_params_in = false, bool cb_save_regs_in = false,
            bool binds_frame_reg_in = false)
        : ar(a), tri(t), vm_abi(abi == AbiKind::VM),
          has_vm_alloca(has_vm_alloca_in), out_stack_args(out_stack_args_in),
          cb_save_regs(cb_save_regs_in) {
        resolver.timeline =
            &ar.timeline; // el resolver consulta el modelo temporal
        SZ = t.pointer_size ? t.pointer_size : 8u;
        k = static_cast<uint32_t>(ar.frame.callee_saved_used.size());
        total_saved = k + (vm_abi ? 1u : 0u); // +1 por el push rbx
        /* Hoja frameless: una funcion sin CALLs que no spillea ni
         * reserva allocas no necesita frame pointer.  RBP solo
         * direcciona spill slots y el area de allocas; sin ellos se
         * omite todo el frame (push rbp / mov rbp,rsp / sub rsp / lea /
         * pop rbp).  Es SEGURO respecto a la GC: el precise stack-scan
         * camina la cadena RBP, pero solo en un SAFEPOINT, y una hoja
         * no tiene safepoint (no llama a nada) -> ningun frame de hoja
         * esta vivo cuando corre la GC.  Aun en VM_ABI se conserva el
         * push/pop de RBX (callee-saved del host que trae ProcessVM*) y
         * los callee-saved usados; lo unico que desaparece es RBP. */
        no_frame = !has_calls && ar.frame.num_spill_slots == 0u &&
                   alloca_total == 0u && !has_vm_alloca &&
                   !has_stack_params_in && /* params en pila -> [rbp+off]
                  necesita el frame pointer estable (push rbp; mov rbp,rsp). */
                   !cb_save_regs_in && /* save-set del callback: la work-area de
                  128B vive en el frame ([rbp-...]) -> necesita frame estable +
                  su reserva en spill_bytes (sub rsp). */
                   !jit_no_frameless() &&
                   !osr::contador_activado(); /* el trigger (1b) añade un
                  call -> necesita frame con rsp 16-alineado. */
        /* FPO: la funcion liga rbp/rsp a un param (register("rbp")).  Ese
         * fisico no puede ser el frame pointer -> NO se emite `mov rbp,rsp` y
         * el frame se direcciona por RSP (frame_below = distancia
         * rbp-hipotetico a rsp). Se conserva push/pop rbp (callee-saved).  Solo
         * hoja: con RSP variable (calls/allocas VM) no habria base estable ->
         * ahi cae al frame normal (y el binding a rbp seguira siendo
         * responsabilidad del programador). */
        fpo = binds_frame_reg_in && !has_calls && !has_vm_alloca &&
              !cb_save_regs_in && !osr::contador_activado();
        if (fpo) no_frame = false; // FPO tiene su propio prologo/epilogo
        /* Las allocas viven debajo de los spill slots. */
        alloca_base = SZ * total_saved + SZ * ar.frame.num_spill_slots;
        spill_bytes =
            static_cast<int32_t>(SZ * ar.frame.num_spill_slots + alloca_total);
        /*   reservar un qword para el VM-RSP salvado, debajo del
         * area de allocas host y por encima del shadow space.  El
         * offset es fijo desde RBP (independiente del shadow/align que
         * se añade despues, que solo crece el frame hacia abajo). */
        if (has_vm_alloca) {
            vm_rsp_save_off = -static_cast<int32_t>(
                8u * total_saved + 8u * ar.frame.num_spill_slots +
                alloca_total + 8u);
            spill_bytes += 8;
        }
        /* Callback save-set: reservar 128B (16 qwords) debajo de todo lo
         * anterior (spills + allocas + vm_rsp) para salvar regs[0..15] del
         * caller VM.  cb_save_base_off = offset del slot del reg 0 (los demas
         * hacia abajo, -r*8).  no_frame es false (cuerpo no-hoja -> has_calls).
         */
        if (cb_save_regs) {
            cb_save_base_off =
                -(static_cast<int32_t>(8u * total_saved) + spill_bytes + 8);
            spill_bytes += 128;
        }
        if (!no_frame) {
            /* stack_arg_base = offset RSP del primer arg por pila.  Win64
             * reserva 32 de shadow ANTES de los stack args (el callee lee
             * arg5 en [rsp+32]); SysV no tiene shadow (arg7 en [rsp+0]).
             * Detectado por el numero de GP arg_regs del TARGET (4=Win64,
             * 6=SysV) -> correcto tambien en AOT cross-target. */
            const size_t gareg_n =
                tri.arg_regs[static_cast<size_t>(RegClass::GP)].size();
            stack_arg_base = (gareg_n == 4) ? 32 : 0;
            /* La convencion de Windows exige que el llamante reserve sitio
             * en la pila para los cuatro primeros argumentos, aunque viajen en
             * registro: el llamado puede escribir ahi.  Se reserva al FONDO del
             * marco (debajo de las ranuras) para que no pise nuestros datos.
             *
             * Se reconoce por el numero de registros de argumento del OBJETIVO
             * -- el mismo criterio que la linea de arriba -- y no por el
             * sistema en el que se compilo esto. */
            if (has_calls && gareg_n == 4) spill_bytes += 32;
            /* Args ilimitados: reservar el outgoing area (slots GP por
             * pila) encima del shadow.  Stack-arg j vive en
             * [rsp + stack_arg_base + j*8] en cada call. */
            if (out_stack_args > 0)
                spill_bytes +=
                    static_cast<int32_t>(out_stack_args) * word_bytes();
            /* Alinear (SZ*total_saved + spill_bytes) a 16 para mantener
             * el stack 16-aligned en CALLs internos.  Con slots de 4
             * (x86-32) el desalineo puede ser 4/8/12 -> padding exacto. */
            {
                const uint32_t cur =
                    SZ * total_saved + static_cast<uint32_t>(spill_bytes);
                spill_bytes += static_cast<int32_t>((16u - (cur % 16u)) % 16u);
            }
        }
        /* Frameless: spill_bytes queda en 0 (no hay spills ni allocas) y
         * no se alinea a 16 ni se reserva shadow space porque no hay
         * CALLs internos. */
        /* FPO: offset para convertir [rbp+off] (off<0 en los slots) a
         * [rsp + frame_below + off].  frame_below = distancia entre el RBP
         * hipotetico (rsp_entrada - SZ, por el push rbp) y el rsp final (tras
         * push callee-saved + sub rsp, spill_bytes).  Se computa con el
         * spill_bytes FINAL (ya alineado arriba). */
        frame_below = static_cast<int32_t>(SZ * total_saved) + spill_bytes;
        const auto &sc = tri.scratch[static_cast<size_t>(RegClass::GP)];
        if (sc.size() >= 1) scr0_ = static_cast<MReg>(sc[0]);
        if (sc.size() >= 2) scr1_ = static_cast<MReg>(sc[1]);
        const auto &fsc = tri.scratch[static_cast<size_t>(RegClass::FP)];
        if (fsc.size() >= 1) fscr0_ = static_cast<MReg>(fsc[0]);
        if (fsc.size() >= 2) fscr1_ = static_cast<MReg>(fsc[1]);
    }

    /// Argumento pendiente de la proxima CALL: indice DENTRO DE SU CLASE,
    /// ubicacion fisica resuelta, y si es de clase FP (-> XMM arg_reg, MOVSD).
    struct PendingArg {
        uint8_t idx;
        MOperand loc;
        bool is_fp;
        /// ABI custom: registro fisico de destino (>=0) tomado de register() en
        /// el param/tipo cfn.  -1 = ABI estandar (usa arg_regs[idx]).  El
        /// selector lo pone en @c MInstr::dst del pseudo-ARG.
        int custom_reg = -1;
    };
    std::vector<PendingArg> pending_args;

    ///  D.7 commit 6: intervalos (para stackmaps en CALLs) +
    /// posicion lineal del CALL actual + stackmaps acumulados.
    const IntervalResult *ivs = nullptr;
    uint32_t cur_call_pos = 0;
    std::vector<Stackmap> stackmaps;

    /**
     * @brief Emite un PARALLEL MOVE: el conjunto de copias
     *        @c dst_reg <- src se realiza simultaneamente.  Emite en
     *        un orden seguro y rompe ciclos con @p scratch.
     */
    void emit_parallel_moves(std::vector<std::pair<MReg, MOperand>> moves,
                             MReg scratch, std::vector<MInstr> &out) const {
        // Secuenciacion via el modulo COMPARTIDO (codegen::sequence_parallel_
        // moves): mismo algoritmo que el interp.  Codificamos el src registro
        // por su id; un src NO-registro (MEM/derrame) va con sentinela
        // negativo -(i+1) (nunca lee un dst; su MOperand se recupera del
        // vector original).  El vreg solo EMITE cada paso como un MOp::MOV.
        std::vector<codegen::PMoveStep> steps;
        steps.reserve(moves.size());
        for (size_t i = 0; i < moves.size(); ++i) {
            const int dst = reg_id(moves[i].first);
            const int src = (moves[i].second.kind == MOperandKind::REG)
                                ? static_cast<int>(moves[i].second.reg)
                                : -static_cast<int>(i + 1);
            steps.push_back({dst, src});
        }
        for (const auto &st : codegen::sequence_parallel_moves(
                 std::move(steps), reg_id(scratch))) {
            const MOperand src_op =
                (st.src >= 0) ? reg(static_cast<MReg>(st.src))
                              : moves[static_cast<size_t>(-st.src - 1)].second;
            out.push_back(MInstr::make_unary(
                MOp::MOV, reg(static_cast<MReg>(st.dst)), src_op));
        }
    }

    /** @brief Registro en el que llega el @c ProcessVM*: es el primer
     *         argumento, asi que lo dice la convencion del objetivo. */
    MReg proc_arg_reg() const noexcept { return arg_reg(0); }

    /** @brief Offset desde RBP del spill slot @p slot. */
    /** @brief Geometria del marco: quien sabe situar una ranura. */
    FrameGeom geom() const noexcept {
        FrameGeom g;
        g.fpo = fpo;
        g.below = frame_below;
        g.slot_size = SZ;
        g.total_saved = total_saved;
        return g;
    }

    int32_t slot_off(uint32_t slot) const noexcept {
        return geom().slot_off(slot);
    }

    MOperand frame_mem(int32_t off) const noexcept { return geom().mem(off); }

    /**
     * @brief Registro en el que viaja el argumento entero numero @p i.
     *
     * Lo dice el OBJETIVO.  Las secuencias que llaman al runtime (el fallo de
     * pagina de la memoria de la VM, la captura del estado de un bucle) tienen
     * que colocar sus argumentos donde la convencion los espera, y eso cambia
     * entre Windows y el resto, y otra vez en 32 bits.
     *
     * @param i Numero de argumento (0 = el primero).
     * @return El registro; @c MReg::RAX si la convencion no llega a tantos,
     *         que no ocurre con los tres primeros en ninguna de las vigentes.
     */
    MReg arg_reg(size_t i) const noexcept {
        const auto &a = tri.arg_regs[static_cast<size_t>(RegClass::GP)];
        return i < a.size() ? static_cast<MReg>(a[i]) : MReg::RAX;
    }

    /** @copydoc FrameGeom::size_for_scan */
    uint32_t frame_size_for_scan() const noexcept {
        return geom().size_for_scan(
            spill_bytes > 0 ? static_cast<uint32_t>(spill_bytes) : 0u);
    }

    MOperand slot_mem(uint32_t slot) const noexcept {
        return geom().slot_mem(slot);
    }

    /**
     * @brief Traduce una @c ValueLocation a operando fisico (registro o slot de
     * stack). El Rewrite pregunta is_register()/is_stack() -- NUNCA compara un
     * enum ni lee un slot a pelo.  DEUDA: @c slot_mem SUPONE que "en memoria"
     * == spill slot; el dia que la memoria pueda ser home location / remat /
     * frame temporal, esto es otra traduccion (ver @c value_location.h).
     */
    MOperand to_operand(codegen::ValueLocation rl,
                        uint8_t width) const noexcept {
        if (rl.is_register())
            return MOperand::make_reg(static_cast<MReg>(rl.register_id()),
                                      width);
        if (rl.is_memory()) return slot_mem(rl.stack_slot());
        /* NINGUNA ubicacion.  Antes esta rama no existia -- "no se donde vive"
         * caia en la de memoria y @c stack_slot() devolvia 0, asi que se
         * convertia en un acceso al SLOT 0.  Un slot que puede no existir: si
         * la funcion no derrama, el frame se omite entero y ese acceso escribe
         * por el RBP del LLAMANTE. Fue exactamente el fallo que rompio el AOT
         * (bucle infinito o SIGSEGV segun lo que hubiera debajo), y aguanto
         * oculto porque el JIT nunca produce este caso -- fail-open puro: el
         * error se disfrazaba de ubicacion valida.
         *
         * Ahora es RUIDOSO.  En builds de comprobacion aborta con el sitio
         * exacto; en release cae al scratch, que existe siempre y no corrompe
         * memoria ajena: si el valor esta muerto da igual, y si no lo esta el
         * fallo se ve, no se pudre. */
#ifdef VM_DEBUG_CHECKS
        std::fprintf(
            stderr,
            "[rewrite] BUG: ValueLocation sin ubicacion en gi=%u -- el "
            "timeline no sabe donde vive este valor\n",
            resolver.cur_gi);
        std::abort();
#endif
        return MOperand::make_reg(scr0(), width);
    }
    /* El Rewrite pregunta por el MOMENTO del operando (use/def), nunca por la
     * posicion; el resolver traduce el momento a una @c ValueLocation.  Quien
     * conoce el rol (el que recorre la instruccion) invoca la resolucion
     * adecuada -- resolve_* no lo deduce. */
    MOperand resolve_use(const MOperand &o) const noexcept {
        return o.is_vreg()
                   ? to_operand(resolver.resolve_use(o.vreg_id()), o.width)
                   : o;
    }
    MOperand resolve_def(const MOperand &o) const noexcept {
        return o.is_vreg()
                   ? to_operand(resolver.resolve_def(o.vreg_id()), o.width)
                   : o;
    }
    /**
     * @brief Materializa UN movimiento entre dos ubicaciones.  UNICO sitio que
     * decide QUE secuencia hace falta; el bucle del Rewrite solo pide "mueve
     * esto alli".
     *
     * Aqui crecen los casos SIN que el Rewrite cambie una linea: hoy un MOV, y
     * el caso memoria->memoria -- que x86 no admite directo -- descompuesto via
     * scratch.  Manana: MOVSD/MOVSS segun la clase del valor, LEA, recomputar
     * un valor rematerializable, cualquier otra secuencia.  Esa decision NO
     * pertenece al Rewrite.
     *
     * TODO (al llegar planes con valores FP): elegir el mnemonico por la clase
     * del vreg (MOVSD/MOVSS en vez de MOV).  Hoy ningun productor genera planes
     * -> no se emite nada.
     */
    void emit_move(codegen::ValueLocation from, codegen::ValueLocation to,
                   bool is_fp, std::vector<MInstr> &out) const {
        if (from == to) return; // ya esta donde debe: nada que mover.
        if (from.is_none() || to.is_none())
            return; // sin ubicacion: nada que materializar.
        /* Se decide primero la ESTRATEGIA (por el par de ubicaciones + la CLASE
         * del valor) y solo despues se TRADUCE lo que esa rama necesita.
         * Importa el orden: cuando existan ubicaciones que no son un operando
         * (una constante, un valor rematerializable), @c to_operand no podra
         * construir un MOperand para ellas y su rama emitira otra cosa (un
         * inmediato, un recomputo, un LEA).  Asi @c to_operand sigue siendo un
         * traductor PURO ValueLocation -> MOperand y no genera codigo.
         *
         * La CLASE decide el opcode: un valor float vive en un XMM y mover un
         * XMM con el
         * @c MOV entero produciria un registro EQUIVOCADO (el encoder leeria el
         * id como GP).  Es un fallo silencioso, asi que se elige aqui, no en la
         * traduccion. */
        const MOp mov = is_fp ? MOp::MOVSD : MOp::MOV;
        if (from.is_memory() && to.is_memory()) {
            // x86 no admite "mov mem, mem": descomponer via scratch del
            // rewrite.  El scratch tambien es de la clase del valor (un GP no
            // puede transportar un XMM).
            const MOperand tmp =
                is_fp ? MOperand::make_reg(fscr0(), SZ) : reg(scr0());
            out.push_back(MInstr::make_unary(mov, tmp, to_operand(from, SZ)));
            out.push_back(MInstr::make_unary(mov, to_operand(to, SZ), tmp));
            return;
        }
        // registro <- registro | registro <- memoria | memoria <- registro: un
        // movimiento.
        out.push_back(
            MInstr::make_unary(mov, to_operand(to, SZ), to_operand(from, SZ)));
    }

    /** @brief Emite los movimientos que el @c TransitionPlanner exige en un
     * punto.  El Rewrite no los calcula ni los interpreta: delega cada uno en
     * @c emit_move -- solo aporta el dato que el planner no tiene, la CLASE del
     * valor (el modelo temporal habla de UBICACIONES; de que tipo es el valor
     * lo sabe el nivel de instrucciones). */
    void emit_transitions(const std::vector<codegen::ValueTransition> &ts,
                          const IntervalResult *ivs,
                          std::vector<MInstr> &out) const {
        for (const codegen::ValueTransition &t : ts) {
            const bool is_fp = ivs && t.vreg < ivs->intervals.size() &&
                               ivs->intervals[t.vreg].cls == RegClass::FP;
            emit_move(t.from, t.to, is_fp, out);
        }
    }

    /* NO hay helpers de "spilled"/"slot_of": pertenecian al modelo ANTIGUO
     * (spill).  El call site pregunta al resolver por el MOMENTO del operando y
     * lee la
     * @c ValueLocation -- @c resolver.resolve_def(vid).is_memory() /
     * .stack_slot(), o
     * @c resolver.resolve_at(v, pos) para los GC roots vivos en un CALL.  Asi
     * el Rewrite habla del modelo TEMPORAL ("¿donde vive este valor en este
     * momento?"), no de spills. */

    /** @brief True si @p o es un valor de coma flotante (vreg de clase FP o
     *  un registro fisico XMM).  Lo usa @c lower() para enrutar los MOV de
     *  un valor float al MOVSD/MOVSS (no al mov entero). */
    static bool is_fp_operand(const MOperand &o) noexcept {
        if (o.is_vreg()) return o.vreg_class() == RegClass::FP;
        if (o.kind == MOperandKind::REG)
            return is_xmm(static_cast<MReg>(o.reg));
        return false;
    }
    /** @brief MOp de movimiento FP segun el ancho (8 -> MOVSD, 4 -> MOVSS). */
    static MOp fp_mov_for_width(uint8_t w) noexcept {
        return (w == 4) ? MOp::MOVSS : MOp::MOVSD;
    }
    static MOperand xmm(MReg r) { return MOperand::make_reg(r, 8); }

    static MOperand reg(MReg r) { return MOperand::make_reg(r, 8); }
    static MInstr push(MReg r) {
        MInstr i;
        i.op = MOp::PUSH;
        i.src1 = reg(r);
        return i;
    }
    static MInstr pop(MReg r) {
        MInstr i;
        i.op = MOp::POP;
        i.dst = reg(r);
        return i;
    }

    /** @brief Ficha del marco: lo unico que el emisor necesita saber. */
    FrameSpec frame_spec() const {
        FrameSpec f;
        f.naked = naked;
        f.fpo = fpo;
        f.no_frame = no_frame;
        f.spill_bytes = spill_bytes;
        f.slot_size = SZ;
        f.total_saved = total_saved;
        f.callee_saved = ar.frame.callee_saved_used;
        f.bajo_vm = vm_abi;
        if (vm_abi) {
            f.vm.proc_arg = proc_arg_reg();
            f.vm.has_alloca = has_vm_alloca;
            f.vm.rsp_save_off = vm_rsp_save_off;
            f.vm.scratch = scr0();
        }
        return f;
    }

    void emit_prologue(std::vector<MInstr> &out) const {
        emit_frame_prologue(frame_spec(), out);
    }

    void emit_epilogue(std::vector<MInstr> &out) const {
        emit_frame_epilogue(frame_spec(), out);
    }

    /**
     * @brief HOST_LEAF: copia los params entrantes (en los arg_regs del
     *        ABI host) a su ubicacion fisica asignada por el regalloc.
     *
     * El selector emite, al inicio del bloque 0, un @c MOV @c vreg <-
     * @c arg_reg fisico por param (que ancla su intervalo).  Aqui los
     * consumimos: los params SPILLED se escriben a su slot directamente
     * (lee el arg_reg pristino, escribe memoria -- no pisa ningun
     * arg_reg), y los params en REGISTRO se mueven con un PARALLEL-MOVE
     * (que rompe ciclos arg_reg<->home con @c scr1()).  Hacer los spills
     * ANTES garantiza que leen el arg_reg antes de que un move de
     * registro lo sobrescriba.  El prologo nunca toca los arg_regs (son
     * caller-saved en ambos ABIs), por lo que estan intactos aqui.
     *
     * @param instrs Instrucciones del bloque 0 (en forma vreg).
     * @param params @c MFunction::param_vregs.
     * @param out    Destino de las instrucciones fisicas.
     * @return Numero de instrucciones lideres consumidas (el caller las
     *         salta en el lowering normal).
     */
    size_t emit_host_param_loads(const std::vector<MInstr> &instrs,
                                 const std::vector<uint32_t> &params,
                                 std::vector<MInstr> &out) {
        if (vm_abi || params.empty()) return 0;
        std::vector<std::pair<MReg, MOperand>> reg_moves;  // GP
        std::vector<std::pair<MReg, MOperand>> freg_moves; // FP (XMM)
        size_t n = 0;
        /* Los MOV param-init son exactamente los lideres del bloque 0 con
         * dst vreg y src registro fisico (arg_reg).  Para los params FLOAT,
         * el src es un XMM arg-reg (el selector conto el indice float aparte
         * del entero) -> se enrutan a un parallel-move FP via MOVSD.
         *
         * CADA param-init se resuelve en SU posicion: el i-esimo lider del
         * bloque 0 tiene gi=i.  Sin fijar @c cur_gi por param, el 2o+ param se
         * consultaba con la posicion del 1o (o la que quedara), caia FUERA de
         * su rango vivo (el valor nace mas tarde), el timeline contestaba "en
         * ningun sitio" (NONE) y @c to_operand lo disfrazaba de scratch -> el
         * param-load escribia el arg en el scratch, no en el home del param, y
         * su uso posterior leia un registro con basura.  Mismo fallo -- y misma
         * cura -- que @c lower_phi_parallel; solo se ve en el AOT (unico que
         * construye el timeline con RANGOS). */
        const uint32_t saved_gi = resolver.cur_gi;
        while (n < instrs.size() && n < params.size() &&
               instrs[n].op == MOp::MOV && instrs[n].dst.is_vreg() &&
               instrs[n].src1.is_reg()) {
            resolver.cur_gi =
                static_cast<uint32_t>(n); // gi del i-esimo lider = i
            const bool fp =
                is_fp_operand(instrs[n].dst) || is_fp_operand(instrs[n].src1);
            const MOperand dst = resolve_def(instrs[n].dst);
            if (dst.is_reg()) {
                if (fp)
                    freg_moves.emplace_back(static_cast<MReg>(dst.reg),
                                            instrs[n].src1);
                else
                    reg_moves.emplace_back(static_cast<MReg>(dst.reg),
                                           instrs[n].src1);
            } else {
                /* param spilled: escribir el arg_reg al slot ya mismo (lee
                 * el arg_reg pristino antes de cualquier move de registro). */
                out.push_back(MInstr::make_unary(fp ? MOp::MOVSD : MOp::MOV,
                                                 dst, instrs[n].src1));
            }
            ++n;
        }
        resolver.cur_gi =
            saved_gi; // el param-load no altera el recorrido normal
        if (!reg_moves.empty())
            emit_parallel_moves(std::move(reg_moves), scr1(), out);
        if (!freg_moves.empty())
            emit_parallel_moves_fp(std::move(freg_moves), fscr1(), out);
        return n;
    }

    /** @brief PARALLEL MOVE para registros XMM (param-load FP): identico a
     *  @c emit_parallel_moves pero emitiendo MOVSD y rompiendo ciclos con un
     *  scratch XMM.  Las fuentes son siempre XMM arg-regs (no memoria). */
    void emit_parallel_moves_fp(std::vector<std::pair<MReg, MOperand>> moves,
                                MReg scratch, std::vector<MInstr> &out) const {
        // Igual que emit_parallel_moves pero banco XMM (MOp::MOVSD, xmm()); la
        // SECUENCIACION es la misma (codegen::sequence_parallel_moves).
        std::vector<codegen::PMoveStep> steps;
        steps.reserve(moves.size());
        for (size_t i = 0; i < moves.size(); ++i) {
            const int dst = reg_id(moves[i].first);
            const int src = (moves[i].second.kind == MOperandKind::REG)
                                ? static_cast<int>(moves[i].second.reg)
                                : -static_cast<int>(i + 1);
            steps.push_back({dst, src});
        }
        for (const auto &st : codegen::sequence_parallel_moves(
                 std::move(steps), reg_id(scratch))) {
            const MOperand src_op =
                (st.src >= 0) ? xmm(static_cast<MReg>(st.src))
                              : moves[static_cast<size_t>(-st.src - 1)].second;
            out.push_back(MInstr::make_unary(
                MOp::MOVSD, xmm(static_cast<MReg>(st.dst)), src_op));
        }
    }

    /** @brief Resuelve un batch de copias de PHI de una MISMA arista como un
     *  PARALLEL MOVE.  Todas las copias phi_dst_i <- arg_i se leen "a la vez"
     *  en la arista; emitidas SECUENCIALMENTE corrompen si el regalloc asigno
     *  phi_dst_i y arg_j al MISMO fisico (ciclo de permutacion) -- ocurre tras
     *  ssa_coalesce, que aprieta la asignacion.  GP via emit_parallel_moves
     *  (scr1() rompe ciclos con un scratch reservado), FP via _fp (fscr1()).
     * Los dst spilled se escriben primero (leen su src pristino antes de que un
     *  reg-move lo pise). */
    void lower_phi_parallel(
        const std::vector<std::pair<const MInstr *, uint32_t>> &phis,
        std::vector<MInstr> &out) {
        const uint32_t saved_gi = resolver.cur_gi;
        std::vector<std::pair<MReg, MOperand>> reg_moves, freg_moves;
        for (const std::pair<const MInstr *, uint32_t> &pg : phis) {
            const MInstr *p = pg.first;
            /* CADA copia se resuelve en SU posicion.  Se acumulan para
             * emitirlas como un movimiento paralelo, pero eso es una decision
             * de EMISION: no las convierte en una sola instruccion, y cada una
             * sigue definiendo su valor en su propio punto del programa.
             *
             * Resolverlas todas con el @c cur_gi que quedara de la instruccion
             * anterior fue un bug real: las consultas caian FUERA del rango
             * vivo del valor (nace mas tarde), el timeline contestaba "en
             * ningun sitio" y esa respuesta llegaba al codigo disfrazada de
             * ubicacion valida.  Solo se notaba en el AOT porque es el unico
             * que construye el timeline con los rangos; sobre una base plana
             * cualquier posicion contesta lo mismo y el desfase quedaba
             * invisible. */
            resolver.cur_gi = pg.second;
            const bool fp = is_fp_operand(p->dst) || is_fp_operand(p->src1);
            const MOperand dst = resolve_def(p->dst);
            const MOperand src = resolve_use(p->src1);
            /* Self-copy (dst==src, mismo fisico): NO-OP en el parallel move.
             * Incluirlo mete un self-loop en el grafo de dependencias que
             * confunde la deteccion de ciclos de emit_parallel_moves.  Aparece
             * con la coalescencia de phi auto-referenciales (`v = phi[.., v]`
             * -> copia `mov v, v`).  Se salta. */
            if (dst.is_reg() && src.kind == MOperandKind::REG &&
                dst.reg == src.reg)
                continue;
            if (dst.is_reg()) {
                if (fp)
                    freg_moves.emplace_back(static_cast<MReg>(dst.reg), src);
                else
                    reg_moves.emplace_back(static_cast<MReg>(dst.reg), src);
            } else {
                /* dst spilled: store ahora (src pristino).  mem->mem via
                 * scratch reservado. */
                const MReg sc = fp ? fscr1() : scr1();
                const MOp mop = fp ? MOp::MOVSD : MOp::MOV;
                if (src.kind == MOperandKind::MEM) {
                    out.push_back(
                        MInstr::make_unary(mop, fp ? xmm(sc) : reg(sc), src));
                    out.push_back(
                        MInstr::make_unary(mop, dst, fp ? xmm(sc) : reg(sc)));
                } else {
                    out.push_back(MInstr::make_unary(mop, dst, src));
                }
            }
        }
        resolver.cur_gi =
            saved_gi; // el batch no altera la posicion del recorrido
        if (!reg_moves.empty())
            emit_parallel_moves(std::move(reg_moves), scr1(), out);
        if (!freg_moves.empty())
            emit_parallel_moves_fp(std::move(freg_moves), fscr1(), out);
    }

    /** @brief Marshala @c pending_args a los arg_regs del ABI host: los
     *  enteros (GP) con un parallel-move via MOV (scr1() rompe ciclos), los
     *  floats (FP) con un parallel-move via MOVSD a los XMM arg_regs (fscr1()).
     *  Cada arg lleva su indice DENTRO DE SU CLASE.  Limpia @c pending_args.
     *
     *  @param extra_gp Movimiento GP adicional (destino, origen) que entra en
     * el MISMO parallel-move.  Lo usa el CALL indirecto para poner el puntero
     * de destino a salvo: si se copiase antes o despues, el reparto de
     * argumentos podria pisar el registro elegido -- o leer de el un valor que
     * ya se habia sobrescrito.  Formando parte del parallel-move, el orden y
     * los ciclos los resuelve el algoritmo. */
    void marshal_args(std::vector<MInstr> &out,
                      const std::pair<MReg, MOperand> *extra_gp = nullptr) {
        const auto &gareg = tri.arg_regs[static_cast<size_t>(RegClass::GP)];
        const auto &fareg = tri.arg_regs[static_cast<size_t>(RegClass::FP)];
        std::vector<std::pair<MReg, MOperand>> gmoves, fmoves;
        /* Args ilimitados: GP que no caben en arg_regs van por PILA en
         * [rsp + stack_arg_base + (idx-gareg)*8].  (idx, loc). */
        /* (offset_rsp, loc, is_fp): is_fp -> store por MOVSD. */
        std::vector<std::tuple<int32_t, MOperand, bool>> smoves;
        /* G = numero de GP-stack-args (overflow GP).  Los FP-stack van DESPUES
         * en la convencion Vesta-interna -> [base+(G+(fi-fmax))*8].  Espejo de
         * la carga del callee en vreg_select. */
        uint32_t G = 0;
        for (const auto &pa : pending_args)
            if (!pa.is_fp && pa.idx >= gareg.size()) ++G;
        for (const auto &pa : pending_args) {
            if (pa.is_fp) {
                if (pa.idx < fareg.size())
                    fmoves.emplace_back(static_cast<MReg>(fareg[pa.idx]),
                                        pa.loc);
                else {
                    const int32_t off =
                        stack_arg_base +
                        static_cast<int32_t>(G + (pa.idx - fareg.size())) *
                            word_bytes();
                    smoves.emplace_back(off, pa.loc, true);
                }
            } else if (pa.custom_reg >= 0) {
                // ABI custom (register() en el param/cfn): el destino es el
                // registro fisico declarado, NO arg_regs[idx].  Va al
                // parallel-move igual que un arg estandar (rompe ciclos con
                // scr1()).
                gmoves.emplace_back(static_cast<MReg>(pa.custom_reg), pa.loc);
            } else {
                if (pa.idx < gareg.size())
                    gmoves.emplace_back(static_cast<MReg>(gareg[pa.idx]),
                                        pa.loc);
                else {
                    const int32_t off =
                        stack_arg_base +
                        static_cast<int32_t>(pa.idx - gareg.size()) *
                            word_bytes();
                    smoves.emplace_back(off, pa.loc, false);
                }
            }
        }
        /* Stores de stack-args PRIMERO (leen su loc antes del shuffle de los
         * arg_regs).  mem->mem via scr1() (R11, caller-saved, libre aqui) -- NO
         * scr0(): un CALL INDIRECTO captura su func_ptr en scr0() antes de este
         * marshal, y debe sobrevivir (ver el caso MOp::CALL).  scr1() se reusa
         * luego para romper ciclos del parallel-move (secuencial, sin solape).
         * FP via MOVSD (scratch XMM si mem->mem). */
        for (const auto &sm : smoves) {
            const int32_t soff = std::get<0>(sm);
            const MOperand &sloc = std::get<1>(sm);
            const bool sfp = std::get<2>(sm);
            const MOperand dst = MOperand::make_mem(MReg::RSP, soff);
            if (sfp) {
                if (sloc.kind == MOperandKind::MEM) {
                    out.push_back(
                        MInstr::make_unary(MOp::MOVSD, xmm(fscr1()), sloc));
                    out.push_back(
                        MInstr::make_unary(MOp::MOVSD, dst, xmm(fscr1())));
                } else {
                    out.push_back(MInstr::make_unary(MOp::MOVSD, dst, sloc));
                }
            } else if (sloc.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), sloc));
                out.push_back(MInstr::make_unary(MOp::MOV, dst, reg(scr1())));
            } else {
                out.push_back(MInstr::make_unary(MOp::MOV, dst, sloc));
            }
        }
        if (extra_gp != nullptr) gmoves.push_back(*extra_gp);
        if (!gmoves.empty())
            emit_parallel_moves(std::move(gmoves), scr1(), out);
        if (!fmoves.empty())
            emit_parallel_moves_fp(std::move(fmoves), fscr1(), out);
        pending_args.clear();
    }

    /** @brief Reescribe una instr vreg a 0+ instrs fisicas. */

    /* --- Familias de la bajada.  Cada una trata SUS operaciones y dice si
     * la ha tratado; asi el despachador no tiene que saber de antemano a
     * quien le toca cada una, que es justo lo que se equivocaria en
     * silencio cuando se anadiera una operacion nueva. --- */

    /**
     * @brief Coma flotante: movimientos, aritmetica escalar, comparacion y
     *        conversiones entre bancos.
     *
     * @param in  Instruccion con registros virtuales.
     * @param out Donde se acumula lo emitido.
     * @return true si la instruccion era suya y ya esta tratada.
     */
    bool lower_flotante(const MInstr &in, std::vector<MInstr> &out) {
        const MOp op = in.op;
        /* ===== FP-regalloc ( AOT C1 float) ===== */

        /* FP MOV (dst/src de clase float): movimiento de un escalar f64/f32.
         * El selector emite @c MOp::MOV para copias FP, el param-init
         * (@c MOV vr_fp, XMM_arg) y el RET (@c MOV XMM0, vr_fp); aqui se
         * enruta al MOVSD/MOVSS.  Ambos pueden estar en XMM o en un slot de
         * pila (spilled).  x86 no tiene mov mem,mem -> si AMBOS son MEM se
         * pasa por el scratch XMM. */
        MOperand d_res =
            (op == MOp::MOV) ? resolve_def(in.dst) : MOperand::none();
        MOperand s_res =
            (op == MOp::MOV) ? resolve_use(in.src1) : MOperand::none();
        // La clase se decide por (a) la clase declarada del vreg operando, o
        // (b) el REGISTRO FiSICO ASIGNADO por el linear-scan.  Ambos deben
        // coincidir, pero si por cualquier razon divergen (un vreg cuya clase
        // declarada quedo GP pero recibio un XMM), el fisico manda: un MOV a/de
        // un XMM ES un movimiento FP y DEBE emitirse como MOVSD/MOVSS.  Sin
        // esto el encoder enmascararia el XMM al GP homonimo (`mov rax`), lo
        // que (1) corromperia un f64 vivo y (2) haria que el modelo de efectos
        // del scheduler viera W[xmm] cuando el hardware escribe W[rax] ->
        // perderia el hazard WAW y reordenaria a valores incorrectos.
        const bool fp_phys =
            (d_res.is_reg() && is_xmm(static_cast<MReg>(d_res.reg))) ||
            (s_res.is_reg() && is_xmm(static_cast<MReg>(s_res.reg)));
        if (op == MOp::MOV &&
            (is_fp_operand(in.dst) || is_fp_operand(in.src1) || fp_phys)) {
            const MOp mv =
                fp_mov_for_width(in.dst.width ? in.dst.width : in.src1.width);
            MOperand d = d_res;
            MOperand s = s_res;
            if (d.kind == MOperandKind::MEM && s.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(mv, xmm(fscr0()), s));
                out.push_back(MInstr::make_unary(mv, d, xmm(fscr0())));
            } else {
                out.push_back(MInstr::make_unary(mv, d, s));
            }
            return true;
        }

        /* AVX escalar 3-OPERANDOS (VADDSD/VSUBSD/VMULSD/VDIVSD + SS): VX nativo
         * dst = src1 OP src2 con dst != src1 permitido -> NO se legaliza a
         * 2-address (sin el `mov dst,src1`).  Esta es la ventaja que motivo
         * MOps separadas: el regalloc/scheduler las explota como 3-op.  vvvv
         * (src1) DEBE ser reg (materializar si spilled); src2 puede ser MEM (VX
         * reg-reg-mem = load-and-op); dst reg (fscr0() + store si spilled). */
        if (op == MOp::VADDSD || op == MOp::VSUBSD || op == MOp::VMULSD ||
            op == MOp::VDIVSD || op == MOp::VADDSS || op == MOp::VSUBSS ||
            op == MOp::VMULSS || op == MOp::VDIVSS || op == MOp::VXORPS ||
            op == MOp::VANDPS) {
            // VXORPS/VANDPS (fneg/fabs): MOVSD (8B) cubre f64 y f32 (la mascara
            // de signo tiene los bits altos a 0 -> XOR/AND no los altera).
            const bool is_ss = (op == MOp::VADDSS || op == MOp::VSUBSS ||
                                op == MOp::VMULSS || op == MOp::VDIVSS);
            const MOp mv = is_ss ? MOp::MOVSS : MOp::MOVSD;
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand dreg =
                dst_spilled ? xmm(fscr0()) : resolve_def(in.dst);
            MOperand s1 = resolve_use(in.src1);
            if (s1.kind == MOperandKind::MEM) { // vvvv debe ser reg
                out.push_back(MInstr::make_unary(mv, xmm(fscr1()), s1));
                s1 = xmm(fscr1());
            }
            const MOperand s2 =
                resolve_use(in.src2); // reg o MEM (VX lo admite)
            out.push_back(MInstr::make_binary(op, dreg, s1, s2));
            if (dst_spilled)
                out.push_back(
                    MInstr::make_unary(mv, resolve_def(in.dst), dreg));
            return true;
        }

        /* FP arith binaria (3-op pre-legalization): ADDSD/SUBSD/MULSD/DIVSD
         * + variantes SS + XORPS.  Legalizacion 2-address: el dst debe ser un
         * XMM y contener src1 antes de la op (dst = src1 OP src2).  Casos:
         *   - dst spilled -> usar fscr0() como acumulador, store al final.
         *   - src1/src2 spilled -> materializar a XMM (fscr0()/fscr1()) antes.
         *   - anti-dependencia (dst==src2 reg): para no-conmutativas (SUB/DIV)
         *     mover src2 a fscr1() primero. */
        if (op == MOp::ADDSD || op == MOp::SUBSD || op == MOp::MULSD ||
            op == MOp::DIVSD || op == MOp::ADDSS || op == MOp::SUBSS ||
            op == MOp::MULSS || op == MOp::DIVSS || op == MOp::XORPS ||
            op == MOp::ANDPS || op == MOp::MINSD || op == MOp::MAXSD ||
            op == MOp::MINSS || op == MOp::MAXSS) {
            const bool is_ss =
                (op == MOp::ADDSS || op == MOp::SUBSS || op == MOp::MULSS ||
                 op == MOp::DIVSS || op == MOp::MINSS || op == MOp::MAXSS);
            const MOp mv = is_ss ? MOp::MOVSS : MOp::MOVSD;
            const bool commutative =
                (op == MOp::ADDSD || op == MOp::MULSD || op == MOp::ADDSS ||
                 op == MOp::MULSS || op == MOp::XORPS || op == MOp::ANDPS);
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            /* acumulador: el dst fisico si esta en XMM, o fscr0() si spilled.
             */
            const MOperand acc =
                dst_spilled ? xmm(fscr0()) : resolve_def(in.dst);
            MOperand s1 = resolve_use(in.src1);
            MOperand s2 = resolve_use(in.src2);
            auto same_reg = [](const MOperand &a, const MOperand &b) {
                return a.kind == MOperandKind::REG &&
                       b.kind == MOperandKind::REG && a.reg == b.reg;
            };
            /* La op SSE 2-address es `OP dst, src` (dst = dst OP src), el
             * encoder lee dst + src1.  Hay que dejar src1 (s1) en acc y
             * aplicar OP acc, s2.  Cuidado con las anti-dependencias:
             *   - s2 == acc (s2 ya esta en el dst): si es CONMUTATIVA basta
             *     `OP acc, s1` (acc tiene s2; acc = s2 OP s1 = s1 OP s2).  Si
             *     NO es conmutativa (SUB/DIV) hay que salvar s2 a fscr1() antes
             *     de pisar acc con s1.
             *   - en otro caso: `mov acc, s1` (si difieren) y luego
             * materializar s2 a XMM si esta spilled. */
            if (same_reg(s2, acc)) {
                if (commutative) {
                    /* acc ya = s2; aplicar OP acc, s1 (s1 a XMM si MEM). */
                    if (s1.kind == MOperandKind::MEM) {
                        out.push_back(MInstr::make_unary(mv, xmm(fscr1()), s1));
                        s1 = xmm(fscr1());
                    }
                    out.push_back(MInstr::make_unary(op, acc, s1));
                } else {
                    /* salvar s2 (en acc) a fscr1(), poner s1 en acc, OP
                     * acc,fscr1(). */
                    out.push_back(MInstr::make_unary(mv, xmm(fscr1()), s2));
                    if (!same_reg(acc, s1))
                        out.push_back(MInstr::make_unary(mv, acc, s1));
                    out.push_back(MInstr::make_unary(op, acc, xmm(fscr1())));
                }
            } else {
                /* acc = s1 (si difieren). */
                if (!same_reg(acc, s1))
                    out.push_back(MInstr::make_unary(mv, acc, s1));
                /* s2 debe estar en XMM (reg-reg only). */
                if (s2.kind == MOperandKind::MEM) {
                    out.push_back(MInstr::make_unary(mv, xmm(fscr1()), s2));
                    s2 = xmm(fscr1());
                }
                out.push_back(MInstr::make_unary(op, acc, s2));
            }
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    mv,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    acc));
            return true;
        }

        /* FP unaria con dst XMM (SQRTSD/SQRTSS + ROUNDSD): dst = f(src).  src
         * puede estar spilled -> materializar a fscr1(); dst spilled ->
         * fscr0(). ROUNDSD lleva el modo de redondeo en @c variant
         * (floor/ceil/round/ trunc) -> se propaga al MInstr emitido. */
        if (op == MOp::SQRTSD || op == MOp::SQRTSS || op == MOp::ROUNDSD ||
            op == MOp::ROUNDSS) {
            const MOp mv = (op == MOp::SQRTSS || op == MOp::ROUNDSS)
                               ? MOp::MOVSS
                               : MOp::MOVSD;
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? xmm(fscr0()) : resolve_def(in.dst);
            MOperand s = resolve_use(in.src1);
            if (s.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(mv, xmm(fscr1()), s));
                s = xmm(fscr1());
            }
            out.push_back(MInstr::make_unary(op, pdst, s));
            out.back().flags = in.flags;     // propagar MI_FLAG_VX_SCALAR
            out.back().variant = in.variant; // ROUNDSD: modo de redondeo
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    mv,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }

        /* UCOMISD/UCOMISS: comparacion FP (setea flags).  Ambos operandos
         * deben estar en XMM (reg-reg only).  Spilled -> fscr0()/fscr1(). */
        if (op == MOp::UCOMISD || op == MOp::UCOMISS) {
            const MOp mv = (op == MOp::UCOMISS) ? MOp::MOVSS : MOp::MOVSD;
            /* El "dst" de UCOMISD es el primer OPERANDO de la comparacion -- se
             * LEE, no se define (la instruccion solo setea flags).
             * operand_roles lo marca R::USE por eso; hay que resolverlo como
             * USO, no como DEF. Con resolve_def caia en def_point, donde el
             * valor ya no vive: sobre una base plana daba la misma ubicacion y
             * no se notaba, pero con los rangos el timeline contestaba "en
             * ningun sitio" (NONE) -- el fallo que bloqueaba poner rangos en
             * los tres modos. */
            MOperand a = resolve_use(in.dst); // operando A (UCOMISD a, b)
            MOperand b = resolve_use(in.src1);
            if (a.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(mv, xmm(fscr0()), a));
                a = xmm(fscr0());
            }
            if (b.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(mv, xmm(fscr1()), b));
                b = xmm(fscr1());
            }
            out.push_back(MInstr::make_unary(op, a, b));
            out.back().flags = in.flags; // propagar MI_FLAG_VX_SCALAR
            return true;
        }

        /* Conversiones int<->float.  CVTSI2SD/CVTSI2SS: dst XMM <- src GP.
         * CVTTSD2SI/CVTTSS2SI: dst GP <- src XMM.  CVTSS2SD/CVTSD2SS: XMM<-XMM.
         * El operando GP/XMM fuente puede estar spilled (MEM) -> a scratch. */
        if (op == MOp::CVTSI2SD || op == MOp::CVTSI2SS) {
            const MOp mv = (op == MOp::CVTSI2SS) ? MOp::MOVSS : MOp::MOVSD;
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? xmm(fscr0()) : resolve_def(in.dst);
            MOperand s = resolve_use(in.src1); // GP source
            if (s.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), s));
                s = reg(scr0());
            }
            out.push_back(MInstr::make_unary(op, pdst, s));
            out.back().flags = in.flags; // propagar MI_FLAG_VX_SCALAR
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    mv,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }
        if (op == MOp::CVTTSD2SI || op == MOp::CVTTSS2SI) {
            const MOp mv = (op == MOp::CVTTSS2SI) ? MOp::MOVSS : MOp::MOVSD;
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? reg(scr0()) : resolve_def(in.dst);
            MOperand s = resolve_use(in.src1); // XMM source
            if (s.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(mv, xmm(fscr1()), s));
                s = xmm(fscr1());
            }
            out.push_back(MInstr::make_unary(op, pdst, s));
            out.back().flags = in.flags; // propagar MI_FLAG_VX_SCALAR
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }
        if (op == MOp::CVTSS2SD || op == MOp::CVTSD2SS) {
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? xmm(fscr0()) : resolve_def(in.dst);
            MOperand s = resolve_use(in.src1); // XMM source
            if (s.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOVSD, xmm(fscr1()), s));
                s = xmm(fscr1());
            }
            out.push_back(MInstr::make_unary(op, pdst, s));
            out.back().flags = in.flags; // propagar MI_FLAG_VX_SCALAR
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOVSD,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }

        /* MOVQ_GP_XMM (dst XMM <- src GP) / MOVQ_XMM_GP (dst GP <- src XMM):
         * bitcast de bits IEEE entre bancos (float CONST, BITCAST).  El
         * operando fuente puede estar spilled.  El dst spilled tambien. */
        if (op == MOp::MOVQ_GP_XMM) {
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? xmm(fscr0()) : resolve_def(in.dst);
            MOperand s = resolve_use(in.src1); // GP source
            if (s.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), s));
                s = reg(scr0());
            }
            out.push_back(MInstr::make_unary(MOp::MOVQ_GP_XMM, pdst, s));
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOVSD,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }
        if (op == MOp::MOVQ_XMM_GP) {
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? reg(scr0()) : resolve_def(in.dst);
            MOperand s = resolve_use(in.src1); // XMM source
            if (s.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOVSD, xmm(fscr1()), s));
                s = xmm(fscr1());
            }
            out.push_back(MInstr::make_unary(MOp::MOVQ_XMM_GP, pdst, s));
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }
        return false;
    }

    /**
     * @brief Llamadas y retorno: directa, por direccion, por simbolo, cola y
     * RET.
     *
     * @param in  Instruccion con registros virtuales.
     * @param out Donde se acumula lo emitido.
     * @return true si la instruccion era suya y ya esta tratada.
     */
    bool lower_llamada(const MInstr &in, std::vector<MInstr> &out) {
        const MOp op = in.op;
        if (op == MOp::ARG) {
            /* Acumular: (indice-de-clase, ubicacion fisica, es_fp).  El
             * selector ya numera el indice por clase; la clase se toma del
             * operando vreg (in.src1.vreg_class) o, si ya es un reg fisico,
             * de si es XMM.  ABI custom: si el selector puso un reg fisico en
             * @c dst, ese es el destino del arg (register() en el param/cfn).
             */
            const int custom =
                in.dst.is_reg() ? static_cast<int>(in.dst.reg) : -1;
            pending_args.push_back({in.variant, resolve_use(in.src1),
                                    is_fp_operand(in.src1), custom});
            return true;
        }

        /* ===== Callback save-set (jubilacion de slots) ===== */
        if (op == MOp::CB_SAVE_REGS || op == MOp::CB_RESTORE_REGS) {
            /* Expandir con R11 (scratch): copiar los 16 qwords entre
             * proc->registers[r] ([rbx + REGISTERS_OFFSET + r*8]) y la
             * work-area del frame ([rbp + cb_save_base_off - r*8]).  RBX =
             * ProcessVM* (VM_ABI), cargado por LOAD_PROC antes del SAVE. */
            const bool save = (op == MOp::CB_SAVE_REGS);
            for (uint32_t r = 0; r < 16u; ++r) {
                const MOperand vmreg =
                    MOperand::make_mem(MReg::RBX, VESTA_PROC_REGISTERS_OFFSET +
                                                      static_cast<int32_t>(r) *
                                                          VESTA_REGISTER_SIZE);
                const MOperand frame = MOperand::make_mem(
                    MReg::RBP, cb_save_base_off - static_cast<int32_t>(r) * 8);
                if (save) {
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, reg(scr1()), vmreg));
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, frame, reg(scr1())));
                } else {
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, reg(scr1()), frame));
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, vmreg, reg(scr1())));
                }
            }
            return true;
        }

        if (op == MOp::CALL_ABS) {
            /* Parallel-move de los args (GP + FP) a sus arg_regs, luego
             * mov scratch,addr + call scratch. */
            marshal_args(out);
            /* Cargar la direccion (imm64 del pool) en scratch y llamar. */
            out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), in.src1));
            MInstr call;
            call.op = MOp::CALL;
            call.src1 = reg(scr0());
            /* Stackmap (commit 6): describir los GC roots vivos a
             * traves de este call.  El linear_scan los forzo a slots,
             * asi que estan en el stack -> el GC los lee via stackmap.
             * Se asocia al CALL por @c flags (idx); el encoder rellena
             * el pc_offset. */
            if (ivs != nullptr) {
                Stackmap sm;
                sm.frame_size = frame_size_for_scan();
                const uint32_t NVI =
                    static_cast<uint32_t>(ivs->intervals.size());
                for (uint32_t v = 0; v < NVI; ++v) {
                    const LiveInterval &lv = ivs->intervals[v];
                    if (!lv.is_gc() || !lv.covers(cur_call_pos)) continue;
                    if (!resolver
                             .resolve_at(v, codegen::LinearPos{cur_call_pos})
                             .is_memory())
                        continue; // invariante: GC+cross-call -> slot
                    StackmapSlot s;
                    s.rbp_offset = static_cast<int16_t>(slot_off(
                        resolver.resolve_at(v, codegen::LinearPos{cur_call_pos})
                            .stack_slot()));
                    s.gc_kind = static_cast<StackmapGcKind>(
                        static_cast<uint8_t>(lv.gc_kind - 1u));
                    sm.slots.push_back(s);
                }
                call.flags = static_cast<uint16_t>(stackmaps.size());
                stackmaps.push_back(std::move(sm));
            }
            out.push_back(call);
            return true;
        }

        if (op == MOp::CALL_SYM) {
            /* AOT: CALL rel32 a una funcion del modulo por nombre.  Igual
             * marshalling que CALL_ABS (parallel-move de los args a los
             * arg_regs del ABI host), pero la llamada es un CALL DIRECTO
             * rel32 (no via scratch): el encoder deja un placeholder +
             * MReloc{CALL_REL32} con el sym_idx que viaja en src1. */
            marshal_args(out);
            MInstr call;
            call.op = MOp::CALL_SYM;
            call.src1 = in.src1;
            /*  AOT-GC (Inc 1): describir los GC roots vivos a traves de
             * este call (gc<T>).  El linear_scan los forzo a slots; el GC los
             * lee via el stackmap.  Antes se omitia ("BARE sin GC"); ahora el
             * gc<T> opt-in los necesita.  Vacio (0 slots) si no hay valores GC
             * vivos -> cero coste para el codigo sin GC. */
            if (ivs != nullptr) {
                Stackmap sm;
                sm.frame_size = frame_size_for_scan();
                const uint32_t NVI =
                    static_cast<uint32_t>(ivs->intervals.size());
                for (uint32_t v = 0; v < NVI; ++v) {
                    const LiveInterval &lv = ivs->intervals[v];
                    if (!lv.is_gc() || !lv.covers(cur_call_pos)) continue;
                    if (!resolver
                             .resolve_at(v, codegen::LinearPos{cur_call_pos})
                             .is_memory())
                        continue;
                    StackmapSlot s;
                    s.rbp_offset = static_cast<int16_t>(slot_off(
                        resolver.resolve_at(v, codegen::LinearPos{cur_call_pos})
                            .stack_slot()));
                    s.gc_kind = static_cast<StackmapGcKind>(
                        static_cast<uint8_t>(lv.gc_kind - 1u));
                    sm.slots.push_back(s);
                }
                call.flags = static_cast<uint16_t>(stackmaps.size());
                stackmaps.push_back(std::move(sm));
            }
            out.push_back(call);
            return true;
        }

        if (op == MOp::MOV_SYM || op == MOp::LEA_RIP_SYM ||
            op == MOp::LEA_LABEL || op == MOp::TLS_LE_ADDR ||
            op == MOp::TLS_PE_ADDR) {
            /* AOT: dst = &simbolo (.rodata) o &thread_local (TLS).  MOV_SYM =
             * abs (mov imm64, --no-pie); LEA_RIP_SYM = RIP-rel (lea, default
             * PIC); LEA_LABEL = direccion nativa de un label local (in-JIT
             * catch); TLS_LE_ADDR = direccion por-hilo (mov %fs:0 + lea@tpoff).
             * Resolver el dst vreg a fisico y emitir la instr fisica; el
             * encoder deja el placeholder + MReloc/MFixup.  dst spilled ->
             * scratch + store. */
            MOperand d = resolve_def(in.dst);
            if (d.is_reg()) {
                MInstr m;
                m.op = op;
                m.dst = d;
                m.src1 = in.src1;
                m.src2 = in.src2; /* TLS_PE_ADDR: 2o simbolo (_tls_index) */
                out.push_back(m);
            } else {
                MInstr m;
                m.op = op;
                m.dst = reg(scr0());
                m.src1 = in.src1;
                m.src2 = in.src2;
                out.push_back(m);
                out.push_back(MInstr::make_unary(MOp::MOV, d, reg(scr0())));
            }
            return true;
        }

        if (op == MOp::CALL) {
            /* CALL INDIRECTO (call reg/mem): el target es un vreg (el
             * jit_code del inline-dispatch VM_ABI, o el func_ptr de la
             * vtable en HOST_LEAF CALLIND -- AOT.2.c).  Emite el stackmap
             * de los GC roots vivos a traves del call. */
            MOperand tgt = resolve_use(in.src1);
            /* HOST_LEAF CALLIND: hay ARGs pendientes que marshalar a los
             * arg_regs del ABI host, y el registro donde vive el func_ptr
             * puede ser justo uno de los destinos -- o la FUENTE de otro
             * argumento.  Se resuelve metiendo "refugio <- func_ptr" DENTRO
             * del mismo parallel-move: el algoritmo ya sabe ordenar los
             * movimientos y romper ciclos, asi que el puntero llega intacto
             * sin importar de donde salga ni quien ocupe su sitio.
             *
             * (Antes se copiaba a scr0=R10 ANTES del marshal.  Funcionaba con
             * el ABI estandar, donde R10 no lleva argumentos, pero no con un
             * ABI custom: en la convencion de syscall de Linux R10 ES el 4o
             * argumento, asi que el marshal escribia encima del puntero y el
             * `call` saltaba al valor del argumento.) */
            if (!pending_args.empty()) {
                /* El refugio no puede ser un registro que YA sea destino de
                 * este mismo movimiento en paralelo: dos destinos iguales y
                 * uno pisa al otro.  Son destinos los de ABI custom (registro
                 * declarado) y los de argumento estandar. */
                int refugio = static_cast<int>(scr0());
                bool reclamado[64] = {false};
                const auto &gareg =
                    tri.arg_regs[static_cast<size_t>(RegClass::GP)];
                for (const auto &pa : pending_args) {
                    if (pa.custom_reg >= 0 && pa.custom_reg < 64)
                        reclamado[pa.custom_reg] = true;
                    else if (!pa.is_fp && pa.idx < gareg.size())
                        reclamado[gareg[pa.idx]] = true;
                }
                if (reclamado[static_cast<int>(scr0())]) {
                    /* Se pregunta al OBJETIVO por sus registros de vida corta
                     * en vez de llevar una lista escrita a mano: la lista
                     * anterior nombraba registros de x86-64, asi que no queria
                     * decir nada en otra arquitectura, y ademas incluia
                     * registros de argumento -- que son destinos -- sin
                     * esquivarlos.  El selector ya rechazo el caso en el que no
                     * queda ninguno libre, asi que aqui siempre hay donde
                     * ponerlo.  El segundo temporal queda fuera: es con el que
                     * el propio movimiento en paralelo rompe los ciclos. */
                    const auto &cortos =
                        tri.caller_saved[static_cast<size_t>(RegClass::GP)];
                    for (uint8_t c : cortos) {
                        if (c >= 64 || reclamado[c]) continue;
                        if (c == static_cast<uint8_t>(scr1())) continue;
                        refugio = static_cast<int>(c);
                        break;
                    }
                }
                const MReg refugio_r = static_cast<MReg>(refugio);
                const std::pair<MReg, MOperand> mov_tgt(refugio_r, tgt);
                marshal_args(out, &mov_tgt);
                tgt = reg(refugio_r);
            } else if (tgt.kind == MOperandKind::MEM) {
                /* target spilled -> cargar a scratch antes del call. */
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), tgt));
                tgt = reg(scr0());
            }
            MInstr call;
            call.op = MOp::CALL;
            call.src1 = tgt;
            if (ivs != nullptr) {
                Stackmap sm;
                sm.frame_size = frame_size_for_scan();
                const uint32_t NVI =
                    static_cast<uint32_t>(ivs->intervals.size());
                for (uint32_t v = 0; v < NVI; ++v) {
                    const LiveInterval &lv = ivs->intervals[v];
                    if (!lv.is_gc() || !lv.covers(cur_call_pos)) continue;
                    if (!resolver
                             .resolve_at(v, codegen::LinearPos{cur_call_pos})
                             .is_memory())
                        continue;
                    StackmapSlot s;
                    s.rbp_offset = static_cast<int16_t>(slot_off(
                        resolver.resolve_at(v, codegen::LinearPos{cur_call_pos})
                            .stack_slot()));
                    s.gc_kind = static_cast<StackmapGcKind>(
                        static_cast<uint8_t>(lv.gc_kind - 1u));
                    sm.slots.push_back(s);
                }
                call.flags = static_cast<uint16_t>(stackmaps.size());
                stackmaps.push_back(std::move(sm));
            }
            out.push_back(call);
            return true;
        }

        if (op == MOp::TAILCALL) {
            /* AOT HOST_LEAF tail-call (TCO genuina, src2 = IMM32 sym_idx):
             * parallel-move de los args (ARG) a los arg_regs del ABI host
             * ANTES del teardown (lee las ubicaciones validas con el frame
             * aun montado; los arg_regs son caller-saved -> sobreviven el
             * epilogue) + emit_epilogue + JMP_SYM al callee.  El callee
             * monta su propio frame y su RET retorna al caller original ->
             * pila O(1).  Sin GC en BARE -> sin stackmap. */
            if (!vm_abi && in.src2.kind == MOperandKind::IMM32) {
                marshal_args(out);
                emit_epilogue(out);
                MInstr j;
                j.op = MOp::JMP_SYM;
                j.src1 = in.src2;
                out.push_back(j);
                return true;
            }
            /* TCO con reuso de frame (mismo patron que el frame-swap del
             * OSR 2c): proc -> A0 (sobrevive el teardown por ser
             * caller-saved; el prologue del callee hace mov rbx,A0) +
             * emit_epilogue (desmonta el frame; rsp queda en la return
             * address del caller) + jmp al target.  El RET del callee
             * retorna al caller original -> pila O(1).  No hay GC entre
             * el teardown y la reentrada (sin safepoint/call) -> los args
             * en proc->registers (ya escritos) siguen como roots. */
            const auto &areg = tri.arg_regs[static_cast<size_t>(RegClass::GP)];
            if (vm_abi && !areg.empty())
                out.push_back(MInstr::make_unary(
                    MOp::MOV, reg(static_cast<MReg>(areg[0])), reg(MReg::RBX)));
            emit_epilogue(out);
            /* El salto es DIRECTO en los dos casos, porque en los dos se sabe
             * a donde se va: a la propia funcion (un label) o a la direccion
             * donde el JIT compilo la otra.  Cinco bytes, sin gastar un
             * registro y con el destino a la vista del predictor de saltos.
             *
             * La direccion de la otra funcion son 64 bits y no cabe en el
             * salto, pero la DISTANCIA si: el codificador deja el hueco y lo
             * rellena quien ya conoce la direccion propia.  Antes se
             * materializaba en un registro y se saltaba a traves de el -- doce
             * bytes -- porque al codificar no se sabe la distancia; lo que
             * faltaba no era la informacion, era esperar a tenerla. */
            /* A una ETIQUETA se salta directo siempre: es un salto normal y
             * cualquier objetivo lo sabe emitir.  A una DIRECCION solo si el
             * objetivo dice que sabe -- lo PREGUNTA, porque este reescritor es
             * comun a todos y saber emitirla es de cada uno --.  Quien no sepa,
             * materializa la direccion en un registro y salta a traves de el,
             * que es la forma de siempre y vale en cualquier parte. */
            static const bool no_direct =
                util::flag_on(util::FlagId::NoDirectTailJmp);
            if ((no_direct || !tri.can_jump_to_abs_addr) &&
                in.src1.kind != MOperandKind::LABEL) {
                out.push_back(
                    MInstr::make_unary(MOp::MOV, reg(scr0()), in.src1));
                MInstr ji;
                ji.op = MOp::JMP;
                ji.src1 = reg(scr0());
                ji.flags |= MI_FLAG_TAILCALL;
                out.push_back(ji);
                return true;
            }
            MInstr j;
            j.op = MOp::JMP;
            j.src1 = in.src1; // LABEL (a si misma) o IMM64_IDX (a otra)
            /* Y se DICE que es una cola.  Visto luego, este `jmp` no se
             * distingue de uno normal, y la diferencia importa: una cola pasa
             * argumentos.  Ver @c MI_FLAG_TAILCALL. */
            j.flags |= MI_FLAG_TAILCALL;
            out.push_back(j);
            return true;
        }

        if (op == MOp::RET) {
            /*  NR @Naked: NO emitir el ret IMPLICITO (caida-al-final); el
             * cuerpo (asm) provee la salida real (ret/iretq).  Un ret aqui
             * seria, en el mejor caso, codigo muerto tras un iretq; en el peor,
             * pisaria la convencion de interrupcion.  Pero un `return`
             * EXPLICITO del usuario (MI_FLAG_RET_EXPLICIT, puesto por el
             * selector segun IrInstr::ret_implicit) SI se materializa:
             * read-back a RAX (ya emitido antes) + `ret`, SIN epilogo de frame
             * (emit_epilogue es no-op en naked).  Sin esto, un `@Naked i64 f(){
             * asm{}; return r; }` cae a basura tras el cuerpo por falta de ret.
             */
            if (naked && !(in.flags & MI_FLAG_RET_EXPLICIT)) return true;
            emit_epilogue(out);
            out.push_back(MInstr::make_ret());
            return true;
        }
        return false;
    }

    /**
     * @brief Secuencias de forma fija: division, desplazamiento variable y
     *        atomicas.  Llevan registros impuestos por la ISA.
     *
     * @param in  Instruccion con registros virtuales.
     * @param out Donde se acumula lo emitido.
     * @return true si la instruccion era suya y ya esta tratada.
     */
    bool lower_forma_fija(const MInstr &in, std::vector<MInstr> &out) {
        const MOp op = in.op;
        if (op == MOp::DIVMOD_V) {
            /* dst = src1 / src2 (variant 0) o src1 % src2 (variant 1),
             * signed.  Secuencia x86 con RAX:RDX fijos.  El divisor va a
             * R11 (scr1(), reservado -> nunca es un operando, sin aliasing)
             * ANTES de tocar RAX/RDX, asi cualquier asignacion fisica de
             * los operandos (incluida RAX/RDX) es segura:
             *   mov  r11, divisor      ; divisor leido antes de clobbers
             *   mov  rax, dividendo    ; (no-op si ya en RAX)
             *   cqo                    ; sign-extend RAX -> RDX:RAX
             *   idiv r11               ; RAX=cociente, RDX=resto
             *   mov  dst, rax|rdx
             * DIVMOD_V es call-position -> ningun vreg vivo a traves esta
             * en RAX/RDX (van a callee-saved), asi el clobber es seguro. */
            const MOperand a = resolve_use(in.src1);  // dividendo
            const MOperand b = resolve_use(in.src2);  // divisor
            const bool uns = (in.variant & 2u) != 0u; // bit1 = unsigned
            out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), b));
            out.push_back(MInstr::make_unary(MOp::MOV, reg(MReg::RAX), a));
            if (uns) {
                /* unsigned: RDX = 0 (xor rdx,rdx) + DIV (F7 /6).  Sin cqo:
                 * el dividendo es u64, RDX:RAX = 0:dividendo. */
                out.push_back(MInstr::make_binary(
                    MOp::XOR, reg(MReg::RDX), reg(MReg::RDX), reg(MReg::RDX)));
                out.push_back(
                    MInstr::make_unary(MOp::DIV_U, MOperand{}, reg(scr1())));
            } else {
                /* signed: CQO (sign-extend RAX -> RDX:RAX) + IDIV (F7 /7). */
                MInstr c;
                c.op = MOp::CQO;
                out.push_back(c);
                out.push_back(
                    MInstr::make_unary(MOp::IDIV, MOperand{}, reg(scr1())));
            }
            const MReg res = (in.variant & 1u) ? MReg::RDX : MReg::RAX;
            out.push_back(
                MInstr::make_unary(MOp::MOV, resolve_def(in.dst), reg(res)));
            return true;
        }

        if (op == MOp::SHIFT_V) {
            /* dst = src1 <shift> src2 (cuenta variable).  x86 exige la cuenta
             * en CL: el selector la pineo a RCX (tmp de vida corta).  Usamos
             * R11 (scr1(), reservado) como reg de trabajo -> nunca clobbea un
             * vivo: mov  r11, value    ; value != RCX (interfiere con la
             * cuenta) shift r11, cl      ; CL = RCX (la cuenta) mov  dst, r11
             * variant: 0=SHL, 1=SHR, 2=SAR. */
            const MOperand v = resolve_use(in.src1); // value
            const MOperand c = resolve_use(in.src2); // cuenta (pineada a RCX)
            /* Orden CRITICO: copiar el VALOR a scr1() (r11) ANTES de fijar la
             * cuenta en RCX.  El allocator NO garantiza value != RCX (el
             * comentario historico "value (!= RCX)" era una asuncion FALSA
             * bajo presion de registros): si el valor vive en RCX, fijar la
             * cuenta primero lo pisaria antes de salvarlo -> el shift operaria
             * sobre la cuenta en vez del valor (bug de shift-by-CL con el
             * valor en RCX; interp=correcto, JIT/AOT=corrupto).  Copiando el
             * valor primero queda a salvo en scr1() (reservado, nunca es la
             * cuenta) y despues se puede sobrescribir RCX sin perderlo. */
            out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), v));
            /* Defensivo: garantizar la cuenta en RCX (no-op si el pin la dejo
             * ya ahi; cubre un eventual spill del tmp). */
            if (!(c.kind == MOperandKind::REG &&
                  c.reg == static_cast<uint8_t>(MReg::RCX)))
                out.push_back(MInstr::make_unary(MOp::MOV, reg(MReg::RCX), c));
            const MOp mop = (in.variant == 0u)   ? MOp::SHL
                            : (in.variant == 1u) ? MOp::SHR
                            : (in.variant == 2u) ? MOp::SAR
                            : (in.variant == 3u) ? MOp::ROL
                                                 : MOp::ROR;
            MInstr sh{};
            sh.op = mop;
            sh.dst = reg(scr1());     // r11 = valor de trabajo
            sh.src1 = reg(MReg::RCX); // CL -> el encoder emite la forma 0xD3
            out.push_back(sh);
            out.push_back(
                MInstr::make_unary(MOp::MOV, resolve_def(in.dst), reg(scr1())));
            return true;
        }

        if (op == MOp::ATOMICADD_V) {
            /* lock xadd [addr], val.  dst (in/out) trae delta y sale con el
             * valor viejo; src1 = addr.  SIN registro fijo: dst y addr los
             * asigno el allocator.  Spills -> scr1() (r11) para addr y un
             * caller-saved libre (r10/r9) para el valor.  call-position ->
             * los caller-saved no tienen vregs vivos aparte de estos operandos.
             */
            const MOperand d = resolve_def(in.dst);  // delta in / old out
            const MOperand a = resolve_use(in.src1); // addr
            MReg base;
            if (a.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), a));
                base = scr1();
            } else {
                base = static_cast<MReg>(a.reg);
            }
            MReg valreg;
            const bool val_spilled = (d.kind == MOperandKind::MEM);
            if (val_spilled) {
                /* El valor va a un TEMPORAL, que esta reservado y por tanto
                 * nunca tiene nada vivo dentro.  Los dos casos son
                 * excluyentes: si la direccion venia de memoria, la base es el
                 * segundo temporal y queda libre el primero; si venia en
                 * registro -- y solo un @c register("...") puede haberla
                 * puesto en el primer temporal -- queda libre el segundo.
                 *
                 * Antes se recurria a R9 cuando la base coincidia con el
                 * primero, y R9 SI es asignable: podia tener un valor vivo y
                 * se le escribia encima. */
                valreg = (base != scr0()) ? scr0() : scr1();
                out.push_back(MInstr::make_unary(MOp::MOV, reg(valreg), d));
            } else {
                valreg = static_cast<MReg>(d.reg);
            }
            MInstr xa{};
            xa.op = MOp::LOCK_XADD;
            xa.dst = MOperand::make_mem(base, 0); // [addr]
            xa.src1 = reg(valreg);                // valor (in/out)
            out.push_back(xa);
            if (val_spilled) {
                out.push_back(MInstr::make_unary(MOp::MOV, d, reg(valreg)));
            }
            return true;
        }

        if (op == MOp::ATOMICCAS_V) {
            /* lock cmpxchg [addr], desired.  dst (in/out) esta PRECOLOREADO a
             * RAX (obligado por la ISA de cmpxchg): entra expected, sale old.
             * addr y desired son LIBRES (el precoloreo garantiza que no caen en
             * RAX).  Spills -> scr1() (r11) para addr, caller-saved libre para
             * desired.  call-position: los caller-saved estan libres. */
            const MOperand a = resolve_use(in.src1);   // addr (!= RAX)
            const MOperand des = resolve_use(in.src2); // desired (!= RAX)
            MReg base;
            if (a.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), a));
                base = scr1();
            } else {
                base = static_cast<MReg>(a.reg);
            }
            MReg srcreg;
            if (des.kind == MOperandKind::MEM) {
                /* Mismo criterio que en el sumar-atomico: al temporal libre,
                 * que no puede tener nada vivo. */
                srcreg = (base != scr0()) ? scr0() : scr1();
                out.push_back(MInstr::make_unary(MOp::MOV, reg(srcreg), des));
            } else {
                srcreg = static_cast<MReg>(des.reg);
            }
            MInstr cx{};
            cx.op = MOp::LOCK_CMPXCHG;
            cx.dst = MOperand::make_mem(base, 0); // [addr]
            cx.src1 = reg(srcreg);                // desired
            out.push_back(cx);
            /* El viejo queda en RAX = resolve_def(in.dst) (precoloreado); el
             * selector ya emitio el MOV final dst_ir <- rax_v.  Nada mas que
             * hacer. */
            return true;
        }

        /* LOAD float HOST: dst es un vreg FP -> MOVSD/MOVSS xmm, [addr]. */
        return false;
    }

    /**
     * @brief Acceso a memoria: cargas y almacenes (host y de la VM) y reserva
     * de pila.
     *
     * @param in  Instruccion con registros virtuales.
     * @param out Donde se acumula lo emitido.
     * @return true si la instruccion era suya y ya esta tratada.
     */
    bool lower_memoria(const MInstr &in, std::vector<MInstr> &out) {
        const MOp op = in.op;
        if (op == MOp::LOAD && is_fp_operand(in.dst)) {
            const uint8_t width = static_cast<uint8_t>(in.flags >> 1);
            MOperand a = resolve_use(in.src1);
            MReg addr_reg;
            if (a.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), a));
                addr_reg = scr1();
            } else {
                addr_reg = static_cast<MReg>(a.reg);
            }
            /* P2 SIB: si src2 es IMM32, es el disp fusionado (`[base+disp]`),
             * igual que en la ruta GP de abajo.  Ignorarlo (disp 0) hacia que
             * TODOS los campos float de un struct se leyeran del offset 0: un
             * `struct Rect { Punto min; Punto max; }` con f64 devolvia
             * min.x para max.x, etc. -- silencioso y con valores plausibles. */
            const int32_t fld_disp =
                (in.src2.kind == MOperandKind::IMM32) ? in.src2.value : 0;
            const MOperand mem = MOperand::make_mem(addr_reg, fld_disp);
            const MOp mv = fp_mov_for_width(width ? width : 8);
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? xmm(fscr0()) : resolve_def(in.dst);
            out.push_back(MInstr::make_unary(mv, pdst, mem));
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    mv,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    xmm(fscr0())));
            return true;
        }

        /* STORE float HOST: el valor (src2) es un vreg FP -> MOVSD/MOVSS. */
        if (op == MOp::STORE && is_fp_operand(in.src2)) {
            const uint8_t width = static_cast<uint8_t>(in.flags);
            MOperand a = resolve_use(in.src1);
            MReg addr_reg;
            if (a.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), a));
                addr_reg = scr1();
            } else {
                addr_reg = static_cast<MReg>(a.reg);
            }
            const MOp mv = fp_mov_for_width(width ? width : 8);
            MOperand v = resolve_use(in.src2);
            if (v.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(mv, xmm(fscr0()), v));
                v = xmm(fscr0());
            }
            const MOperand mem = MOperand::make_mem(addr_reg, 0);
            out.push_back(MInstr::make_unary(mv, mem, v));
            return true;
        }

        if (op == MOp::LOAD) {
            /* dst = [addr].  addr y dst pueden estar spilled. */
            const uint8_t width = static_cast<uint8_t>(in.flags >> 1);
            const bool sgn = (in.flags & 1u) != 0u;
            MOperand a = resolve_use(in.src1);
            MReg addr_reg;
            if (a.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), a));
                addr_reg = scr1();
            } else {
                addr_reg = static_cast<MReg>(a.reg);
            }
            /* NO tocar mem.width: empaqueta scale|index del MEM.  El
             * ancho de un MOV [mem] lo da el reg; el de MOVSX/MOVZX va
             * en mem.flags (mem_size override).
             * P2 SIB: si src2 es IMM32, es el disp fusionado (`[base+disp]`).
             */
            const int32_t ld_disp =
                (in.src2.kind == MOperandKind::IMM32) ? in.src2.value : 0;
            MOperand mem = MOperand::make_mem(addr_reg, ld_disp);
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            MOperand pdst = dst_spilled ? reg(scr0()) : resolve_def(in.dst);
            if (width == 8) {
                out.push_back(MInstr::make_unary(MOp::MOV, pdst, mem));
            } else if (width == 4 && !sgn) {
                /* u32: `mov r32, [mem]` zero-extiende a r64 por hardware
                 * (no hay MOVZX de 32->64).  pdst a 32 bits -> sin REX.W. */
                MOperand d32 = pdst;
                if (d32.kind == MOperandKind::REG) d32.width = 4;
                out.push_back(MInstr::make_unary(MOp::MOV, d32, mem));
            } else if (sgn) {
                mem.flags = width; // ancho del src para MOVSX
                out.push_back(MInstr::make_unary(MOp::MOVSX, pdst, mem));
            } else { // u8/u16
                mem.flags = width;
                out.push_back(MInstr::make_unary(MOp::MOVZX, pdst, mem));
            }
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }

        if (op == MOp::STORE) {
            /* [addr] = val.  addr -> scr1() si spilled; val -> scr0() si
             * spilled.
             */
            const uint8_t width = static_cast<uint8_t>(in.flags);
            MOperand a = resolve_use(in.src1);
            MReg addr_reg;
            if (a.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), a));
                addr_reg = scr1();
            } else {
                addr_reg = static_cast<MReg>(a.reg);
            }
            MOperand v = resolve_use(in.src2);
            if (v.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), v));
                v = reg(scr0());
            }
            v.width = width; // ancho del store lo da el reg src
            /* NO tocar mem.width (index packing). */
            MOperand mem = MOperand::make_mem(addr_reg, 0);
            out.push_back(MInstr::make_unary(MOp::MOV, mem, v));
            return true;
        }

        if (op == MOp::LOAD_VM || op == MOp::STORE_VM) {
            /* Acceso a memoria del VM (vaddr, NO host_ptr).  La memoria
             * del VM no es contigua (TLB 3-niveles) -> page-cache INLINE
             * de 1 entrada (replica de selector.cpp): si la pagina del
             * vaddr coincide con la cacheada en proc->vm_mem y no cruza
             * el limite, traduce inline (~hit ~8 instr SIN call); si no,
             * CALL a vrt_vm_read/write_u<w>.  scr0()/scr1() (R10/R11, reserva-
             * dos) son los temporales del hit; areg/val se re-leen de su
             * ubicacion canonica (resolve) en el miss -> intactos.  Es
             * call-position (el miss clobbea caller-saved) -> los vregs
             * vivos a traves ya estan en callee-saved/spill.
             * NOTA: vrt_vm_read/write NO disparan GC (solo traducen) ->
             * el CALL del miss no es safepoint -> sin stackmap. */
            const bool is_store = (op == MOp::STORE_VM);
            const uint8_t width = is_store
                                      ? static_cast<uint8_t>(in.flags)
                                      : static_cast<uint8_t>(in.flags >> 1);
            const bool sgn = !is_store && ((in.flags & 1u) != 0u);
            /* imm64_idx con la direccion de vrt_vm_read/write_u<w>:
             * src2 en LOAD_VM, dst en STORE_VM (operandos libres). */
            const MOperand fn_imm = is_store ? in.dst : in.src2;
            const MOperand areg = resolve_use(in.src1); // vaddr (canonica)
            const MOperand vval = is_store ? resolve_use(in.src2) : MOperand{};
            /* dst del LOAD: reg fisico o scr0() si spilled. */
            const bool dst_spilled =
                !is_store && in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            MReg pr = MReg::RAX;
            if (!is_store)
                pr = dst_spilled ? scr0()
                                 : static_cast<MReg>(resolve_def(in.dst).reg);

            const bool inline_ok = vesta_rt::kProcVmMemOffset != 0 &&
                                   vesta_rt::kVmMemCachedPageVaddrOffset >= 0 &&
                                   vesta_rt::kVmMemCachedPageHostOffset >= 0;
            const int32_t page_v = vesta_rt::kProcVmMemOffset +
                                   vesta_rt::kVmMemCachedPageVaddrOffset;
            const int32_t page_h = vesta_rt::kProcVmMemOffset +
                                   vesta_rt::kVmMemCachedPageHostOffset;
            /* Los tres primeros registros de argumento salen del OBJETIVO, no
             * de en que sistema se compilo esto: son distintos en cada
             * convencion y tambien en 32 bits. */
            const MReg A0 = arg_reg(0), A1 = arg_reg(1), A2 = arg_reg(2);
            const MLabelId Lmiss = inline_ok ? pf->new_label() : MLABEL_INVALID;
            const MLabelId Ldone = inline_ok ? pf->new_label() : MLABEL_INVALID;

            if (inline_ok) {
                /* --- HIT path --- */
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), areg));
                out.push_back(
                    MInstr::make_unary(MOp::MOV, reg(scr0()), reg(scr1())));
                out.push_back(MInstr::make_unary(MOp::AND, reg(scr0()),
                                                 MOperand::make_imm32(-4096)));
                out.push_back(
                    MInstr::make_unary(MOp::CMP, reg(scr0()),
                                       MOperand::make_mem(MReg::RBX, page_v)));
                out.push_back(MInstr::make_jcc(MCond::NE, Lmiss));
                out.push_back(MInstr::make_unary(
                    MOp::AND, reg(scr1()),
                    MOperand::make_imm32(4095))); // scr1 = offset
                if (width > 1) {                  // cross-page check
                    out.push_back(MInstr::make_unary(
                        MOp::CMP, reg(scr1()),
                        MOperand::make_imm32(4096 -
                                             static_cast<int32_t>(width))));
                    out.push_back(MInstr::make_jcc(MCond::A, Lmiss));
                }
                out.push_back(MInstr::make_unary(
                    MOp::MOV, reg(scr0()),
                    MOperand::make_mem(MReg::RBX, page_h))); // cached_host
                out.push_back(
                    MInstr::make_unary(MOp::ADD, reg(scr0()),
                                       reg(scr1()))); // scr0 = host_ptr
                if (is_store) {
                    MOperand v = vval;
                    if (v.kind == MOperandKind::MEM) {
                        out.push_back(
                            MInstr::make_unary(MOp::MOV, reg(scr1()), v));
                        v = reg(scr1());
                    }
                    v.width = width; // ancho lo da el reg
                    out.push_back(MInstr::make_unary(
                        MOp::MOV, MOperand::make_mem(scr0(), 0), v));
                } else {
                    MOperand mem = MOperand::make_mem(scr0(), 0);
                    if (width >= 8) {
                        out.push_back(MInstr::make_unary(
                            MOp::MOV, MOperand::make_reg(pr, 8), mem));
                    } else if (sgn) {
                        mem.flags = width; // mem_size override
                        out.push_back(MInstr::make_unary(
                            MOp::MOVSX, MOperand::make_reg(pr, 8), mem));
                    } else if (width == 4) {
                        out.push_back(MInstr::make_unary(
                            MOp::MOV, MOperand::make_reg(pr, 4),
                            mem)); // zero-ext
                    } else {
                        mem.flags = width;
                        out.push_back(MInstr::make_unary(
                            MOp::MOVZX, MOperand::make_reg(pr, 8), mem));
                    }
                }
                out.push_back(MInstr::make_jmp(Ldone));
                out.push_back(MInstr::make_label_def(Lmiss));
            }

            /* --- FALLBACK CALL (page-miss) ---
             * Cargo vaddr (y val) a scratch ANTES de los arg-movs para
             * no depender del orden de los arg_regs (robusto ante
             * cualquier ubicacion fisica de areg/vval). */
            out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), areg));
            if (is_store) {
                /* val a scr0() (reg o mem, mov reg,* lo cubre). */
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), vval));
                out.push_back(
                    MInstr::make_unary(MOp::MOV, reg(A0), reg(MReg::RBX)));
                out.push_back(
                    MInstr::make_unary(MOp::MOV, reg(A1), reg(scr1())));
                out.push_back(
                    MInstr::make_unary(MOp::MOV, reg(A2), reg(scr0())));
                out.push_back(
                    MInstr::make_unary(MOp::MOV, reg(scr0()), fn_imm));
                MInstr call;
                call.op = MOp::CALL;
                call.src1 = reg(scr0());
                out.push_back(call);
            } else {
                out.push_back(
                    MInstr::make_unary(MOp::MOV, reg(A0), reg(MReg::RBX)));
                out.push_back(
                    MInstr::make_unary(MOp::MOV, reg(A1), reg(scr1())));
                out.push_back(
                    MInstr::make_unary(MOp::MOV, reg(scr0()), fn_imm));
                MInstr call;
                call.op = MOp::CALL;
                call.src1 = reg(scr0());
                out.push_back(call);
                /* resultado en RAX -> pr (igual que el selector). */
                if (sgn && width < 8) {
                    MOperand src = MOperand::make_reg(MReg::RAX, width);
                    out.push_back(MInstr::make_unary(
                        MOp::MOVSX, MOperand::make_reg(pr, 8), src));
                } else {
                    out.push_back(MInstr::make_unary(
                        MOp::MOV, MOperand::make_reg(pr, 8), reg(MReg::RAX)));
                }
            }

            if (inline_ok) out.push_back(MInstr::make_label_def(Ldone));
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    reg(scr0())));
            return true;
        }

        if (op == MOp::ALLOCA) {
            /* dst = host_ptr a `size` bytes reservados en el frame
             * (debajo de los spills).  LEA dst, [rbp - off]. */
            const uint32_t size = static_cast<uint32_t>(in.src1.value);
            const uint32_t aligned = (size + 7u) & ~7u;
            const int32_t off =
                static_cast<int32_t>(alloca_base + alloca_cursor + aligned);
            alloca_cursor += aligned;
            const MOperand mem = frame_mem(-off);
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? reg(scr0()) : resolve_def(in.dst);
            out.push_back(MInstr::make_unary(MOp::LEA, pdst, mem));
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }

        if (op == MOp::ALLOCA_VM) {
            /* dst = vaddr a `size` bytes del VM stack del proceso:
             *   mov scr0(), [rbx+SP]; sub scr0(), aligned; mov [rbx+SP],scr0()
             *   dst = scr0().
             * scr0() (R10) es scratch reservado; RBX trae el ProcessVM*.
             * El prologue ya salvo el VM-RSP original y el epilogue lo
             * restaura, asi que la resta es local al frame. */
            const uint32_t size = static_cast<uint32_t>(in.src1.value);
            const uint32_t aligned = (size + 15u) & ~15u; // 16-align
            const MOperand sp_mem =
                MOperand::make_mem(MReg::RBX, VESTA_PROC_STACK_POINTER_OFFSET);
            out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), sp_mem));
            if (aligned > 0)
                out.push_back(MInstr::make_unary(
                    MOp::SUB, reg(scr0()),
                    MOperand::make_imm32(static_cast<int32_t>(aligned))));
            out.push_back(MInstr::make_unary(MOp::MOV, sp_mem, reg(scr0())));
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    reg(scr0())));
            else
                out.push_back(MInstr::make_unary(MOp::MOV, resolve_def(in.dst),
                                                 reg(scr0())));
            return true;
        }
        return false;
    }

    /**
     * @brief Aritmetica, logica, movimientos y comparacion enteros.
     *
     * Aqui vive la legalizacion a dos operandos: la ISA escribe el
     * resultado ENCIMA de una fuente, asi que un `dst = a OP b` con tres
     * nombres distintos hay que reescribirlo, y cuidando de no pisar `b`
     * al copiar `a`.
     *
     * @param in  Instruccion con registros virtuales.
     * @param out Donde se acumula lo emitido.
     * @return true si la instruccion era suya y ya esta tratada.
     */
    bool lower_alu(const MInstr &in, std::vector<MInstr> &out) {
        const MOp op = in.op;
        if (op == MOp::MOV) {
            const MOperand rs = resolve_use(in.src1);
            if (in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory()) {
                const uint32_t slot =
                    resolver.resolve_def(in.dst.vreg_id()).stack_slot();
                if (rs.kind == MOperandKind::REG) {
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, slot_mem(slot), rs));
                } else {
                    /* mem<-mem o mem<-imm: pasar por scratch. */
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, reg(scr0()), rs));
                    out.push_back(MInstr::make_unary(MOp::MOV, slot_mem(slot),
                                                     reg(scr0())));
                }
            } else {
                /* dst no-spilled (reg) o dst MEM fisico (p.ej. el
                 * return VM a [rbx+off]).  Si AMBOS son MEM (dst MEM
                 * fisico + src spilled), pasar por scratch (no hay
                 * mov mem,mem en x86). */
                const MOperand d = resolve_def(in.dst);
                if (d.kind == MOperandKind::MEM &&
                    rs.kind == MOperandKind::MEM) {
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, reg(scr0()), rs));
                    out.push_back(MInstr::make_unary(MOp::MOV, d, reg(scr0())));
                } else {
                    out.push_back(MInstr::make_unary(MOp::MOV, d, rs));
                }
            }
            return true;
        }

        if (op == MOp::MOVZX || op == MOp::MOVSX) {
            /* Extension: dst64 <- src<width>.  El encoder exige
             * dst=REG; si el src esta spilled, cargarlo a scratch1
             * preservando su width; si el dst esta spilled, extender
             * a scratch0 y almacenar. */
            MOperand rs = resolve_use(in.src1);
            if (rs.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), rs));
                rs = MOperand::make_reg(scr1(), in.src1.width); // width del src
            }
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? reg(scr0()) : resolve_def(in.dst);
            MInstr ext;
            ext.op = op;
            ext.dst = pdst;
            ext.src1 = rs;
            out.push_back(ext);
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }

        if (op == MOp::SHL || op == MOp::SHR || op == MOp::SAR ||
            op == MOp::ROL || op == MOp::ROR) {
            /* dst = src1 (sh/rot) src2(imm).  MOV dst, src1; SHL dst, imm.
             * Solo cantidad INMEDIATA (el selector emite ROL/ROR aqui solo
             * con count constante; variable -> fallback, requiere CL). */
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? reg(scr0()) : resolve_def(in.dst);
            const MOperand rs1 = resolve_use(in.src1);
            if (!(pdst.kind == MOperandKind::REG &&
                  rs1.kind == MOperandKind::REG && pdst.reg == rs1.reg))
                out.push_back(MInstr::make_unary(MOp::MOV, pdst, rs1));
            MInstr sh;
            sh.op = op;
            sh.dst = pdst;
            sh.src1 = in.src2; // imm
            out.push_back(sh);
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }

        if (op == MOp::LZCNT || op == MOp::TZCNT || op == MOp::POPCNT) {
            /* dst = op(src).  dst debe ser REG (si spilled -> scratch
             * + store).  src puede ser MEM (op r64, r/m64). */
            const MOperand rs = resolve_use(in.src1);
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? reg(scr0()) : resolve_def(in.dst);
            out.push_back(MInstr::make_unary(op, pdst, rs));
            if (dst_spilled)
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            return true;
        }

        if (op == MOp::BSWAP) {
            /* bswap r64: in-place, dst debe ser REG.  Si dst spilled,
             * cargar a scratch, bswap, store.  src1 == dst (mismo vreg). */
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            if (dst_spilled) {
                const MOperand sl = slot_mem(
                    resolver.resolve_def(in.dst.vreg_id()).stack_slot());
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), sl));
                out.push_back(
                    MInstr::make_unary(MOp::BSWAP, reg(scr0()), reg(scr0())));
                out.push_back(MInstr::make_unary(MOp::MOV, sl, reg(scr0())));
            } else {
                const MOperand pdst = resolve_def(in.dst);
                out.push_back(MInstr::make_unary(MOp::BSWAP, pdst, pdst));
            }
            return true;
        }

        if (op == MOp::CMOVCC) {
            /* dst = (cc) ? src : dst  (read-modify).  dst debe ser REG.
             * Preserva variant (codigo de condicion).  src spilled -> scr1();
             * dst spilled -> carga a scr0(), cmov, store. */
            MOperand rsrc = resolve_use(in.src1);
            if (rsrc.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr1()), rsrc));
                rsrc = reg(scr1());
            }
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            MInstr c;
            c.op = MOp::CMOVCC;
            c.variant = in.variant;
            if (dst_spilled) {
                const MOperand sl = slot_mem(
                    resolver.resolve_def(in.dst.vreg_id()).stack_slot());
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), sl));
                c.dst = reg(scr0());
                c.src1 = rsrc;
                out.push_back(c);
                out.push_back(MInstr::make_unary(MOp::MOV, sl, reg(scr0())));
            } else {
                c.dst = resolve_def(in.dst);
                c.src1 = rsrc;
                out.push_back(c);
            }
            return true;
        }

        if (is_bin_alu(op)) {
            const bool dst_spilled =
                in.dst.is_vreg() &&
                resolver.resolve_def(in.dst.vreg_id()).is_memory();
            const MOperand pdst =
                dst_spilled ? reg(scr0()) : resolve_def(in.dst);
            const MOperand rs1 = resolve_use(in.src1);
            const MOperand rs2 = resolve_use(in.src2);

            /* P3 imm-forms: IMUL con src2 inmediato -> forma 3-op NO
             * destructiva `imul pdst, src1, imm` (0x69/0x6B).  Ahorra el
             * `mov pdst, src1` del 2-address.  src1 debe ser reg (si spilled,
             * a scratch); el encoder no acepta un imul con fuente en memoria.
             */
            if (op == MOp::IMUL && in.src2.kind == MOperandKind::IMM32) {
                MOperand s1 = rs1;
                if (s1.kind == MOperandKind::MEM) {
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, reg(scr1()), s1));
                    s1 = reg(scr1());
                }
                out.push_back(
                    MInstr::make_binary(MOp::IMUL, pdst, s1, in.src2));
                if (dst_spilled)
                    out.push_back(MInstr::make_unary(
                        MOp::MOV,
                        slot_mem(resolver.resolve_def(in.dst.vreg_id())
                                     .stack_slot()),
                        pdst));
                return true;
            }

            const bool anti =
                (rs2.kind == MOperandKind::REG &&
                 pdst.kind == MOperandKind::REG && rs2.reg == pdst.reg);
            /* IMUL (emit_imul) SOLO soporta reg,reg y reg,reg,imm -- NO
             * acepta un operando fuente en memoria (a diferencia de
             * ADD/SUB/AND/OR/XOR, cuyo emit_alu si maneja r/m).  Si el
             * operando fuente del imul de 2 operandos esta spilled
             * (MEM), cargarlo a scr1() primero.  Sin esto, un imul con un
             * src spilled (p.ej. una constante loop-invariante que el
             * regalloc spilleo bajo presion) caia al fallback 0xCC del
             * encoder -> SIGTRAP en runtime. */
            auto imul_fix = [&](MOperand src) -> MOperand {
                if (op == MOp::IMUL && src.kind == MOperandKind::MEM) {
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, reg(scr1()), src));
                    return reg(scr1());
                }
                return src;
            };
            /* P3 lea-3op: `dst = src1 + src2` con dst, src1, src2 en
             * REGISTROS DISTINTOS (3-address puro) -> `lea dst, [src1+src2]`
             * en UNA instr (vs `mov dst,src1; add dst,src2`) y SIN tocar
             * flags (util justo antes de un consumidor de flags).  Solo ADD
             * (lea suma, no resta).  Se descarta si:
             *   - !anti garantiza pdst != rs2 (el otro sumando).
             *   - pdst != rs1 (si coalescieron, ya es `add dst,src2` 1-instr).
             *   - alguno de los sumandos es RSP/RBP: RSP no puede ser index en
             *     SIB y RBP-base fuerza disp32; ademas esos NUNCA son valores
             *     computados (frame reservado) -> descartar sin perder nada. */
            if (op == MOp::ADD && !anti && pdst.kind == MOperandKind::REG &&
                rs1.kind == MOperandKind::REG &&
                rs2.kind == MOperandKind::REG && pdst.reg != rs1.reg &&
                rs1.reg != static_cast<uint8_t>(MReg::RSP) &&
                rs1.reg != static_cast<uint8_t>(MReg::RBP) &&
                rs2.reg != static_cast<uint8_t>(MReg::RSP) &&
                rs2.reg != static_cast<uint8_t>(MReg::RBP)) {
                out.push_back(MInstr::make_unary(
                    MOp::LEA, pdst,
                    MOperand::make_mem(static_cast<MReg>(rs1.reg), 0,
                                       static_cast<MReg>(rs2.reg), 1)));
                if (dst_spilled)
                    out.push_back(MInstr::make_unary(
                        MOp::MOV,
                        slot_mem(resolver.resolve_def(in.dst.vreg_id())
                                     .stack_slot()),
                        pdst));
                return true;
            }
            if (anti) {
                if (is_commutative(op)) {
                    /* pdst ya contiene src2 -> OP pdst, src1 (conmutativo). */
                    out.push_back(MInstr::make_unary(op, pdst, imul_fix(rs1)));
                } else {
                    /* SUB y pdst==src2reg: usar scratch1 para src2. */
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, reg(scr1()), rs2));
                    out.push_back(MInstr::make_unary(MOp::MOV, pdst, rs1));
                    out.push_back(MInstr::make_unary(op, pdst, reg(scr1())));
                }
            } else {
                /* Elide el `mov pdst, src1` identidad cuando el regalloc ya
                 * coalescio dst y src1 al mismo fisico (mismo criterio que el
                 * path de shifts).  Quita un mov redundante por cada ALU
                 * 2-address coalescida. */
                if (!(pdst.kind == MOperandKind::REG &&
                      rs1.kind == MOperandKind::REG && pdst.reg == rs1.reg))
                    out.push_back(
                        MInstr::make_unary(MOp::MOV, pdst, rs1)); // pdst = src1
                out.push_back(
                    MInstr::make_unary(op, pdst,
                                       imul_fix(rs2))); // pdst OP= src2
            }
            if (dst_spilled) {
                out.push_back(MInstr::make_unary(
                    MOp::MOV,
                    slot_mem(
                        resolver.resolve_def(in.dst.vreg_id()).stack_slot()),
                    pdst));
            }
            return true;
        }

        if (op == MOp::CMP || op == MOp::TEST) {
            MOperand a = resolve_use(in.src1);
            MOperand b = resolve_use(in.src2);
            if (a.kind == MOperandKind::MEM && b.kind == MOperandKind::MEM) {
                out.push_back(MInstr::make_unary(MOp::MOV, reg(scr0()), a));
                a = reg(scr0());
            }
            out.push_back(MInstr::make_unary(op, a, b)); // dst=a, src1=b
            return true;
        }
        return false;
    }

    /**
     * @brief Baja UNA instruccion con registros virtuales a instrucciones de
     *        la maquina, preguntando a cada familia si es suya.
     *
     * Cada familia dice si ha tratado la instruccion en vez de decidirlo aqui
     * por adelantado: si el despachador tuviera que saber a quien le toca cada
     * operacion, anadir una nueva se equivocaria en silencio -- caeria al
     * final, se le sustituirian los registros y saldria codigo que parece
     * bueno.  Lo que no es de nadie llega al final a proposito, que es donde
     * viven las que solo necesitan eso (saltos, etiquetas).
     *
     * @param in  Instruccion con registros virtuales.
     * @param out Donde se acumula lo emitido.
     */
    void lower(const MInstr &in, std::vector<MInstr> &out) {
        if (lower_llamada(in, out)) return;
        if (lower_flotante(in, out)) return;
        if (lower_forma_fija(in, out)) return;
        if (lower_memoria(in, out)) return;
        if (lower_alu(in, out)) return;

        /* Resto (JMP/JCC/LABEL_DEF/NOP/...): sustituir vregs en sitio. */
        MInstr m = in;
        m.dst = resolve_def(in.dst);
        m.src1 = resolve_use(in.src1);
        m.src2 = resolve_use(in.src2);
        out.push_back(m);
    }
};

} // namespace

MFunction rewrite_to_physical(const MFunction &vf,
                              const codegen::AllocationResult &alloc,
                              const TargetRegInfo &tri, AbiKind abi,
                              const IntervalResult *ivs, OsrEmit *osr) {
    /* Detectar si la funcion tiene CALLs (para reservar shadow space). */
    bool has_calls = false;
    uint32_t alloca_total = 0;  // commit 8: bytes de allocas en el frame
    bool has_vm_alloca = false; //   reserva en el VM stack del proceso
    for (const auto &b : vf.blocks) {
        for (const auto &in : b.instrs) {
            if (in.op == MOp::CALL || in.op == MOp::CALL_ABS) has_calls = true;
            /* CALL_SYM (AOT): CALL rel32 a una funcion del modulo -> frame
             * con shadow space (Win64) + rsp 16-alineado, igual que CALL. */
            if (in.op == MOp::CALL_SYM) has_calls = true;
            /* LOAD_VM/STORE_VM: el page-miss emite un CALL a vrt_vm_*; aunque
             * el hit no llama, debe reservarse el frame + shadow space Win64
             * (no frameless). */
            if (in.op == MOp::LOAD_VM || in.op == MOp::STORE_VM)
                has_calls = true;
            /* TAILCALL: su expansion hace emit_epilogue (necesita el frame
             * montado: lea rsp,[rbp-...] + pops) -> forzar frame (no
             * frameless), igual que un call normal. */
            if (in.op == MOp::TAILCALL) has_calls = true;
            if (in.op == MOp::ALLOCA) {
                const uint32_t sz = static_cast<uint32_t>(in.src1.value);
                alloca_total += (sz + 7u) & ~7u;
            }
            if (in.op == MOp::ALLOCA_VM) has_vm_alloca = true;
        }
    }
    /* Args ilimitados (JIT/AOT): max numero de GP args por PILA en cualquier
     * call (overflow de arg_regs).  Reset por call group; toma el maximo
     * para dimensionar el outgoing area del frame una sola vez. */
    uint32_t max_stack_args = 0;
    {
        const size_t gareg_n =
            tri.arg_regs[static_cast<size_t>(RegClass::GP)].size();
        const size_t fareg_n =
            tri.arg_regs[static_cast<size_t>(RegClass::FP)].size();
        uint32_t gp_in_call = 0, fp_in_call = 0;
        for (const auto &b : vf.blocks) {
            for (const auto &in : b.instrs) {
                if (in.op == MOp::ARG) {
                    if (Lowerer::is_fp_operand(in.src1))
                        ++fp_in_call;
                    else
                        ++gp_in_call;
                } else if (in.op == MOp::CALL || in.op == MOp::CALL_ABS ||
                           in.op == MOp::CALL_SYM) {
                    /* Stack-args = overflow GP + overflow FP (van DESPUES de
                     * los GP-stack -> el total dimensiona el outgoing area). */
                    uint32_t s = 0;
                    if (gp_in_call > gareg_n)
                        s += gp_in_call - static_cast<uint32_t>(gareg_n);
                    if (fp_in_call > fareg_n)
                        s += fp_in_call - static_cast<uint32_t>(fareg_n);
                    if (s > max_stack_args) max_stack_args = s;
                    gp_in_call = 0;
                    fp_in_call = 0;
                }
            }
        }
    }
    /* Incoming stack-params (callee): si hay mas params que arg_regs GP, los de
     * overflow llegan en la pila ([rbp+off]) -> hay que FORZAR el frame pointer
     * (no_frame=false) para que rbp sea estable.  Conservador (cuenta total de
     * params): un falso positivo solo reserva un frame de mas, nunca corrompe.
     */
    const bool has_stack_params =
        vf.param_vregs.size() >
        tri.arg_regs[static_cast<size_t>(RegClass::GP)].size();
    Lowerer lw(alloc, tri, abi, has_calls, alloca_total, has_vm_alloca,
               max_stack_args, has_stack_params, vf.cb_save_regs,
               vf.binds_frame_reg);
    /* Los movimientos que exige el modelo temporal (cuando un valor cambia de
     * ubicacion entre tramos).  El Rewrite NO los calcula: pregunta por punto
     * del programa y emite. Sin afirmaciones en el plan el planner esta vacio
     * -> no se emite nada. */
    const codegen::TransitionPlanner transitions(alloc.timeline);
    lw.naked = vf.naked; //  NR @Naked: sin prologo/epilogo/ret
    lw.ivs = ivs;        // commit 6: para construir stackmaps en CALLs
    MFunction pf;
    lw.pf = &pf; // labels intra-expansion (LOAD_VM/STORE_VM page-cache)
    pf.name = vf.name;
    /* Para QUE objetivo, que aqui SI se sabe: es el descriptor con el que se
     * reparte.  Quien pregunte luego por los efectos de una instruccion lo
     * necesita, y sin decirlo cogeria el del anfitrion -- que en un binario
     * cruzado es otra convencion --.  Ver @c MFunction::target. */
    pf.target = &tri;
    /* Y que registros FIJA, que quien mira la liveness necesita: una llamada a
     * una funcion que pega sus parametros a registros concretos los lee ahi y
     * no en los de la convencion.  Ver @c MFunction::pinned_regs. */
    pf.pinned_regs = vf.pinned_regs; // lo que el selector ya anoto
    for (const int8_t r : vf.vreg_fixed)
        if (r >= 0 && r < 64) pf.pinned_regs |= (1ull << r);
    /* Solo-LSP (vista "Godbolt"): propagar el opt-in de la tabla
     * byte_offset -> source_line al MFunction fisico (que es el que ve el
     * encoder).  OFF por defecto -> sin efecto en produccion. */
    pf.emit_line_map = vf.emit_line_map;
    pf.next_label_id = vf.next_label_id;
    pf.label_offsets = vf.label_offsets;
    pf.imm64_pool = vf.imm64_pool;
    /* AOT: la tabla de simbolos de las relocations viaja del MFunction
     * vreg al fisico; el encoder (que corre sobre @c pf) appendea las
     * @c MReloc referenciando estos indices. */
    pf.reloc_symbols = vf.reloc_symbols;
    /*  AS inc.5: los bytes del inline-asm los consume el ENCODER, que
     * corre sobre @c pf (la funcion reescrita) -> hay que arrastrarlos.
     * (@c vreg_fixed NO se copia: lo consume @c build_intervals, que corre
     * sobre @c vf ANTES del rewrite.) */
    pf.asm_blobs = vf.asm_blobs;
    /* Y de paso se DEJA DICHO que registros fisicos lee y escribe cada bloque.
     *
     * Sus listas hablan de registros VIRTUALES, y el mapa a fisicos se queda
     * aqui: sin escribirlo, el MachineIR ya repartido no se describe a si mismo
     * y quien lo mire despues ve un `asm` que aparentemente no lee nada --
     * porque sus lecturas no estan en los operandos --.  Se descubrio cuando
     * una regla de mirilla borro un `mov` que alimentaba a un asm.
     *
     * Los operandos de un asm van PINEADOS, asi que su sitio no cambia y basta
     * con preguntar donde le toco.  Si a alguno no le toco registro, se deja
     * fuera: el propio ensamblado diferido lo cuenta como fallo mas abajo. */
    for (AsmBlob &b : pf.asm_blobs) {
        const auto a_fisico = [&alloc, &vf](const std::vector<uint32_t> &vregs,
                                            std::vector<uint8_t> &out) {
            out.clear();
            out.reserve(vregs.size());
            for (const uint32_t v : vregs) {
                /* El PIN manda, y se mira primero: un `register("rax") u64 q`
                 * tiene su registro decidido antes de repartir, y preguntarselo
                 * al reparto puede no contestar.  Es el mismo orden que sigue
                 * el ensamblado diferido con @c fixed_phys. */
                const int pin = (v < vf.vreg_fixed.size())
                                    ? static_cast<int>(vf.vreg_fixed[v])
                                    : -1;
                if (pin >= 0) {
                    out.push_back(static_cast<uint8_t>(pin));
                    continue;
                }
                const auto loc = alloc.timeline.first_location(v);
                if (loc.is_register())
                    out.push_back(static_cast<uint8_t>(loc.register_id()));
            }
        };
        a_fisico(b.in_vregs, b.in_phys);
        a_fisico(b.out_vregs, b.out_phys);
    }
    /* ENSAMBLADO DIFERIDO.  Los blobs de un `asm ( reg x )` con
     * operandos AUTO llegan sin bytes: su plantilla lleva $N y el fisico de
     * cada operando lo acaba de elegir el asignador.  Sustituimos $N por el
     * registro real (@c ra.reg_of del vreg, o el pin @c fixed_phys) y llamamos
     * al ensamblador.  Asi el operando `reg` se integra con el regalloc de la
     * funcion (registro OPTIMO) en vez del pick greedy compile-time. */
    for (AsmBlob &b : pf.asm_blobs) {
        if (!b.deferred) continue;
        const AsmDeferredResult res = asm_deferred_assemble(b, alloc, vf);
        if (res.ok) {
            b.bytes = std::move(res.bytes);
        } else {
            /* Sin bytes el bloque no emite nada, asi que se cuenta: un
             * programa que compila y hace otra cosa es peor que uno que no
             * compila.  El modulo devuelve DATOS; la frase se pone aqui, que
             * es el sitio que sabe a quien se le habla.  Cuando el catalogo
             * multi-idioma llegue a esta capa, esto pasa a ser un codigo VXNNNN
             * con sus argumentos y el texto sale de ahi. */
            /* Y ademas se MARCA, que contarlo no basta.  Hasta ahora esto
             * imprimia y seguia, y la frase de arriba se quedaba en buena
             * intencion: la funcion salia compilada con un bloque que no emite
             * nada.  Se veia en `std.memory`, cuyas variantes SIMD entregaban
             * una copia a medias -- y solo bajo JIT, porque el interprete usa
             * la version de bucle. */
            if (res.fallo != AsmDeferredFallo::NINGUNO &&
                res.fallo != AsmDeferredFallo::SIN_ENSAMBLADOR)
                pf.asm_sin_bytes = true;
            switch (res.fallo) {
            case AsmDeferredFallo::SIN_REGISTRO:
                std::fprintf(stderr,
                             "[asm] en '%s': al operando $%u no le ha tocado "
                             "registro (clase %u, vreg %u, en memoria=%d); el "
                             "banco del objetivo no da para tantos operandos a "
                             "la vez\n",
                             vf.name.c_str(), res.operando, (unsigned)res.clase,
                             res.vreg, res.en_memoria ? 1 : 0);
                break;
            case AsmDeferredFallo::SIN_NOMBRE:
                std::fprintf(stderr,
                             "[asm] en '%s': la ranura %d no se puede nombrar "
                             "para el operando $%u (clase %u, ancho %u)\n",
                             vf.name.c_str(), res.ranura, res.operando,
                             (unsigned)res.clase, (unsigned)res.ancho);
                break;
            case AsmDeferredFallo::NO_ENSAMBLA:
                std::fprintf(stderr,
                             "[asm] en '%s': no ensambla tras poner los "
                             "registros: %s\ncuerpo:\n%s\n",
                             vf.name.c_str(), res.detalle.c_str(),
                             res.texto.c_str());
                break;
            case AsmDeferredFallo::SIN_ENSAMBLADOR:
            case AsmDeferredFallo::NINGUNO:
            default: break; // sin ensamblador no hay nada que contar
            }
        }
        if (util::flag_on(util::FlagId::AsmTrampDebug)) {
            std::fprintf(stderr,
                         "=== plantilla (%zu ops) ===\n%s\n"
                         "=== asm con registros puestos ===\n%s\n",
                         b.deferred_ops.size(), b.deferred_tmpl.c_str(),
                         res.texto.c_str());
        }
        b.deferred = false; // resuelto (o fallido -> sin bytes, no emite)
    }
    pf.blocks.resize(vf.blocks.size());

    /* OSR 1a: deteccion PRECISA de loop back-edges via DFS (clasico:
     * arista u->v es back-edge sii v esta "gris" = en la pila del DFS).
     * Distingue ciclos reales de saltos a un indice menor que NO son loops
     * (e.g. el merge de un if/else anidado).  @c be_block[u]=1 si el bloque
     * u termina en un BR INCONDICIONAL (succ_b invalido) que es back-edge.
     * Iterativo para no desbordar la pila en funciones con muchos bloques. */
    const size_t NB = vf.blocks.size();
    std::vector<uint8_t> be_block; // vacio salvo con el gate (cero overhead)
    if (osr::contador_activado() && NB > 0) {
        be_block.assign(NB, 0);
        std::vector<uint8_t> color(NB, 0);         // 0=white 1=gray 2=black
        std::vector<std::pair<MBlockId, int>> stk; // (bloque, prox succ)
        stk.push_back({0, 0});
        color[0] = 1;
        while (!stk.empty()) {
            MBlockId u = stk.back().first;
            int &si = stk.back().second;
            const MBlockId succ[2] = {vf.blocks[u].succ_a, vf.blocks[u].succ_b};
            if (si < 2) {
                const MBlockId v = succ[si];
                ++si;
                if (v == MBLOCK_INVALID || v >= NB) continue;
                if (color[v] == 0) {
                    color[v] = 1;
                    stk.push_back({v, 0});
                } else if (color[v] == 1) {
                    /* back-edge u->v; instrumentable solo si u es BR
                     * incondicional (sin succ_b) y v es ese succ_a. */
                    if (vf.blocks[u].succ_b == MBLOCK_INVALID &&
                        vf.blocks[u].succ_a == v)
                        be_block[u] = 1;
                }
            } else {
                color[u] = 2;
                stk.pop_back();
            }
        }
    }

    /* OSR 2a: indice global de la primera instr de cada bloque (MISMA
     * numeracion que build_intervals).  @c block_start[h] = 2*first_gi[h]
     * es la posicion del header; @c covers(block_start[h]) == el live-in
     * del header (los valores que C2 debe reanudar).  Solo bajo el gate. */
    std::vector<uint32_t> first_gi;
    if ((osr::contador_activado() || osr != nullptr) && NB > 0) {
        first_gi.assign(NB, 0);
        uint32_t g = 0;
        for (size_t bb = 0; bb < NB; ++bb) {
            first_gi[bb] = g;
            g += static_cast<uint32_t>(vf.blocks[bb].instrs.size());
        }
    }

    /* gi = indice lineal global de la instr vreg (MISMO orden que
     * build_intervals).  cur_call_pos = 2*gi se pasa a lower() para que
     * el CALL_ABS sepa que GC roots estan vivos en ese punto. */
    uint32_t gi = 0;
    for (size_t b = 0; b < vf.blocks.size(); ++b) {
        pf.blocks[b].label_id = vf.blocks[b].label_id;
        pf.blocks[b].succ_a = vf.blocks[b].succ_a;
        pf.blocks[b].succ_b = vf.blocks[b].succ_b;
        pf.blocks[b].extra_succs = vf.blocks[b].extra_succs;
        std::vector<MInstr> outv;
        outv.reserve(vf.blocks[b].instrs.size() * 2 + 8);
        if (b == 0) {
            lw.emit_prologue(outv);
            /* Y se anota QUE marco quedo montado y CUANTAS instrucciones ocupa,
             * para poder describirselo al sistema.  Sin esa descripcion, un
             * fallo del procesador dentro de esta funcion no se puede recoger:
             * ver @c MFunction::UnwindDesc. */
            const FrameSpec fs = lw.frame_spec();
            pf.prologue_instrs = static_cast<uint32_t>(outv.size());
            pf.unwind.naked = fs.naked;
            /* `fpo` salva RBP pero NO lo apunta a la pila: el marco se
             * direcciona por RSP.  Para el desenrollador son dos cosas
             * distintas y hay que decirlas por separado. */
            pf.unwind.push_rbp = !fs.naked && (fs.fpo || !fs.no_frame);
            pf.unwind.frame_ptr = !fs.naked && !fs.fpo && !fs.no_frame;
            pf.unwind.push_rbx = !fs.naked && fs.bajo_vm;
            pf.unwind.callee_saved = fs.callee_saved;
            pf.unwind.spill_bytes = fs.naked ? 0u : fs.spill_bytes;
        }
        /* HOST_LEAF: cargar los params desde los arg_regs (parallel-move).
         * Consume las MOV param-init lideres del bloque 0; el lowering
         * normal las salta (pero gi avanza para no desincronizar las
         * posiciones de los stackmaps). */
        size_t param_skip = (b == 0)
                                ? lw.emit_host_param_loads(vf.blocks[0].instrs,
                                                           vf.param_vregs, outv)
                                : 0;
        size_t ii = 0;
        /* Batch de copias de PHI (variant==0xFD): una MISMA arista es un
         * PARALLEL MOVE.  Se acumulan y se resuelven juntas con
         * lower_phi_parallel (rompe ciclos con scratch); si se bajaran una a
         * una via lw.lower(), la emision secuencial corromperia un ciclo de
         * permutacion creado por el regalloc (post ssa_coalesce). */
        std::vector<std::pair<const MInstr *, uint32_t>> pending_phi;
        auto flush_phi = [&]() {
            if (pending_phi.empty()) return;
            lw.lower_phi_parallel(pending_phi, outv);
            pending_phi.clear();
        };
        for (const MInstr &in : vf.blocks[b].instrs) {
            if (ii < param_skip) {
                ++ii;
                ++gi;
                continue;
            }
            ++ii;
            if (in.op == MOp::MOV && in.variant == 0xFD) {
                pending_phi.emplace_back(&in, gi); // acumular CON su posicion
                ++gi;
                continue;
            }
            flush_phi(); // resolver las copias de PHI antes del terminador
            lw.cur_call_pos = 2u * gi;
            lw.resolver.cur_gi =
                gi; // el resolver pregunta use_point/def_point(cur_gi)
            /* Movimientos que el modelo temporal exige ANTES de esta
             * instruccion (el valor debe estar ya en su nueva ubicacion cuando
             * se lea).  Van fuera del line map: no pertenecen a ninguna linea
             * fuente, son codigo de la asignacion. */
            lw.emit_transitions(transitions.before_instruction(gi), ivs, outv);
            /* Solo-LSP: las MInstr fisicas que emite lower() se construyen
             * frescas (make_unary/...), perdiendo el source_pc de @c in.
             * Lo re-estampamos en las instrs anadidas por esta op para que
             * el encoder produzca la tabla linea<->asm.  OFF en produccion. */
            const size_t lm_before = pf.emit_line_map ? outv.size() : 0;
            lw.lower(in, outv);
            if (pf.emit_line_map) {
                for (size_t k = lm_before; k < outv.size(); ++k) {
                    if (in.source_pc != 0 && outv[k].source_pc == 0)
                        outv[k].source_pc = in.source_pc;
                    /* Tambien la identidad de la op IR (correlacion exacta). */
                    if (outv[k].ir_id == 0xFFFFFFFFu) outv[k].ir_id = in.ir_id;
                }
            }
            /* Movimientos exigidos DESPUES de esta instruccion (p.ej. tras
             * definir el valor en un registro, guardarlo en su ubicacion del
             * siguiente tramo). */
            lw.emit_transitions(transitions.after_instruction(gi), ivs, outv);
            ++gi;
        }
        flush_phi(); // por si el bloque termina en copias de PHI
        /* OSR 1a: instrumentar el back-edge (BR incondicional a un bloque
         * anterior).  El counter va ANTES del JMP terminal; el `add` toca
         * flags pero el JMP no las lee.  push/pop rax preserva el estado.
         * Emitido aqui (post-lower) para no pasar por la legalizacion
         * 2-address que mangla ADD [mem],imm. */
        if (osr == nullptr && osr::contador_activado() && be_block[b] &&
            !outv.empty() && outv.back().op == MOp::JMP) {
            osr::instalar_resumen_al_salir();

            /* --- OSR 2a: descriptor del estado vivo del loop header ---
             * Capturamos el live-in del header = covers(2*first_gi[header])
             * = phi_dst (loop-carried) + invariantes usados en el loop
             * (excluye phi_args y temporales del header).  Cada valor se
             * escribira en osr_buffer[vid].  Restringido a IR values reales
             * (vid < ir_value_count): esos ids son ESTABLES entre C1 y C2
             * (el clon C2 los preserva), garantizando que C1 escribe y C2
             * lee la MISMA celda.  Si algun valor no es capturable (temp del
             * selector, fuera del buffer, o sin ubicacion fisica), ABORTA la
             * captura de este loop (el trigger sigue logueando "ABORTADO"). */
            const MBlockId header = vf.blocks[b].succ_a;
            /* Descriptor LOCAL: se llena aqui porque solo este sitio conoce
             * los intervalos y las ubicaciones; luego se entrega al registro.
             */
            struct {
                std::string fn_name;
                uint32_t header_block;
                std::vector<osr::Captura> captures;
                bool aborted;
            } desc;
            desc.header_block = 0;
            desc.aborted = false;
            desc.fn_name = vf.name;
            desc.header_block = header;
            desc.aborted = false;
            if (ivs != nullptr && header != MBLOCK_INVALID &&
                static_cast<size_t>(header) < NB && !first_gi.empty()) {
                const uint32_t header_pos = 2u * first_gi[header];
                const uint32_t NVI =
                    static_cast<uint32_t>(ivs->intervals.size());
                const uint32_t ir_n = vf.ir_value_count;
                for (uint32_t v = 0; v < NVI; ++v) {
                    const LiveInterval &lv = ivs->intervals[v];
                    if (!lv.covers(header_pos)) continue;
                    if (v >= ir_n || v >= VESTA_OSR_BUFFER_N ||
                        alloc.timeline.lookup(v, codegen::LinearPos{header_pos})
                            .is_none()) {
                        desc.aborted = true;
                        desc.captures.clear();
                        break;
                    }
                    desc.captures.push_back(
                        {v, static_cast<uint8_t>(lv.is_gc() ? 1u : 0u)});
                }
            } else {
                desc.aborted = true;
            }
            const bool do_capture = !desc.aborted;
            /* Copia para el codegen (el descriptor se mueve al registro). */
            const std::vector<osr::Captura> caps = desc.captures;
            const uint64_t loop_id =
                osr::registrar_bucle(std::move(desc.fn_name), desc.header_block,
                                     std::move(desc.captures), desc.aborted);

            /* Indices del pool: contador, loop_id, handler. */
            const uint32_t idx_cnt =
                static_cast<uint32_t>(pf.imm64_pool.size());
            pf.imm64_pool.push_back(
                reinterpret_cast<uint64_t>(osr::contador_de_vueltas()));
            const uint32_t idx_lid =
                static_cast<uint32_t>(pf.imm64_pool.size());
            pf.imm64_pool.push_back(loop_id);
            const uint32_t idx_h = static_cast<uint32_t>(pf.imm64_pool.size());
            pf.imm64_pool.push_back(
                reinterpret_cast<uint64_t>(osr::disparador()));
            const MLabelId lskip = pf.new_label();
            auto R = [](MReg r) { return MOperand::make_reg(r, 8); };
            std::vector<MInstr> seq;
            /* --- contador + check (cada iteracion; jne bien predicho) --- */
            seq.push_back(MInstr::make_unary(MOp::PUSH, {}, R(MReg::RAX)));
            seq.push_back(MInstr::make_unary(
                MOp::MOV, R(MReg::RAX), MOperand::make_imm64_idx(idx_cnt)));
            seq.push_back(MInstr::make_unary(MOp::ADD,
                                             MOperand::make_mem(MReg::RAX, 0),
                                             MOperand::make_imm32(1)));
            seq.push_back(MInstr::make_unary(
                MOp::CMP, MOperand::make_mem(MReg::RAX, 0),
                MOperand::make_imm32(static_cast<int32_t>(osr::umbral()))));
            seq.push_back(MInstr::make_unary(MOp::POP, R(MReg::RAX), {}));
            seq.push_back(MInstr::make_jcc(
                MCond::NE, lskip)); // cmp no toca rsp; pop no toca flags
            /* --- trigger one-shot (cnt == umbral): preservar TODO el estado
             * vivo (caller-saved), llamar al handler, restaurar.  RBX
             * (=ProcessVM*) es callee-saved -> sobrevive el call. --- */
            const auto &cs =
                tri.caller_saved[static_cast<size_t>(RegClass::GP)];
            for (uint8_t r : cs)
                seq.push_back(
                    MInstr::make_unary(MOp::PUSH, {}, R(static_cast<MReg>(r))));
            /* Igual que arriba: los argumentos los dice el objetivo.  El hueco
             * que la convencion de Windows exige reservar sobre la pila para
             * los cuatro primeros SI depende de la convencion, y por eso se
             * pregunta por ella y no por el sistema anfitrion. */
            const MReg A0 = lw.arg_reg(0), A1 = lw.arg_reg(1),
                       A2 = lw.arg_reg(2);
            const uint32_t SHADOW = host_is_sysv() ? 0u : 32u;
            /* --- OSR 2a captura: escribir cada vid vivo en osr_buffer[vid].
             * RAX = base del buffer (proc->osr_buffer leido via RBX); RCX =
             * temp.  Ambos son caller-saved (ya salvados en la pila arriba)
             * y se restauran en el pop final.  Las fuentes caller-saved se
             * leen de su COPIA en la pila (offset = 8*(n-1-idx), nunca del
             * reg vivo, que podemos haber clobreado); las callee-saved del
             * reg directo (intactas); las derramadas del slot [rbp+off]. */
            if (do_capture) {
                const size_t n = cs.size();
                seq.push_back(MInstr::make_unary(
                    MOp::MOV, R(MReg::RAX),
                    MOperand::make_mem(MReg::RBX,
                                       VESTA_PROC_OSR_BUFFER_OFFSET)));
                for (const osr::Captura &c : caps) {
                    const MOperand dstmem = MOperand::make_mem(
                        MReg::RAX, static_cast<int32_t>(c.vid * 8u));
                    const codegen::ValueLocation cl = alloc.timeline.lookup(
                        c.vid, codegen::LinearPos{2u * first_gi[header]});
                    if (cl.is_register()) {
                        const uint8_t rid = cl.register_id();
                        int idx = -1;
                        for (size_t i = 0; i < n; ++i)
                            if (cs[i] == rid) {
                                idx = static_cast<int>(i);
                                break;
                            }
                        if (idx >= 0) {
                            /* caller-saved: leer de la copia en la pila. */
                            const int32_t off = static_cast<int32_t>(
                                8u * (n - 1u - static_cast<size_t>(idx)));
                            seq.push_back(MInstr::make_unary(
                                MOp::MOV, R(MReg::RCX),
                                MOperand::make_mem(MReg::RSP, off)));
                            seq.push_back(MInstr::make_unary(MOp::MOV, dstmem,
                                                             R(MReg::RCX)));
                        } else {
                            /* callee-saved: valor vivo en el reg directo. */
                            seq.push_back(MInstr::make_unary(
                                MOp::MOV, dstmem, R(static_cast<MReg>(rid))));
                        }
                    } else { /* spilled: leer del slot rbp-relativo. */
                        seq.push_back(MInstr::make_unary(
                            MOp::MOV, R(MReg::RCX),
                            MOperand::make_mem(MReg::RBP,
                                               lw.slot_off(cl.stack_slot()))));
                        seq.push_back(
                            MInstr::make_unary(MOp::MOV, dstmem, R(MReg::RCX)));
                    }
                }
                /* arg2 = base del buffer (sigue en RAX tras la captura). */
                seq.push_back(
                    MInstr::make_unary(MOp::MOV, R(A2), R(MReg::RAX)));
            } else {
                /* sin captura: arg2 = 0 (el handler no lee el buffer). */
                seq.push_back(MInstr::make_unary(MOp::MOV, R(A2),
                                                 MOperand::make_imm32(0)));
            }
            seq.push_back(
                MInstr::make_unary(MOp::MOV, R(A0), R(MReg::RBX))); // arg0=proc
            seq.push_back(MInstr::make_unary(
                MOp::MOV, R(A1),
                MOperand::make_imm64_idx(idx_lid))); // arg1=loop_id
            /* Alinear rsp a 16 + shadow space (Win64).  Tras el frame rsp
             * esta 16-alineado; push de C caller-saved lo desalinea 8 si C
             * es impar. */
            const uint32_t adjust = ((cs.size() & 1u) ? 8u : 0u) + SHADOW;
            if (adjust)
                seq.push_back(MInstr::make_unary(
                    MOp::SUB, R(MReg::RSP),
                    MOperand::make_imm32(static_cast<int32_t>(adjust))));
            seq.push_back(MInstr::make_unary(MOp::MOV, R(MReg::RAX),
                                             MOperand::make_imm64_idx(idx_h)));
            {
                MInstr c;
                c.op = MOp::CALL;
                c.src1 = R(MReg::RAX);
                seq.push_back(c);
            }
            /* --- 2c FRAME-SWAP: el handler devolvio en RAX la direccion del
             * OSR-entry del C2 (o 0).  Si != 0, ABANDONAMOS el frame C1 y
             * saltamos al C2: emit_epilogue restaura el frame con
             * `lea rsp,[rbp-8*total_saved]` (ABSOLUTO desde rbp -> no hay que
             * deshacer los push del trigger) + pops, dejando rsp en la
             * direccion de retorno del CALLER de C1.  RAX (osr_entry) NO se
             * popea en el epilogue -> sobrevive.  `jmp rax` entra al C2 con
             * rsp en ret_addr: el RET del C2 retorna al caller de C1, como si
             * el C2 hubiera sido la funcion llamada.  El buffer-por-VID ya
             * tiene el estado (capturado arriba, antes del handler) y el
             * handler es lookup-puro (sin GC) -> host_ptr GC siguen frescos. */
            const MLabelId lcont = pf.new_label();
            seq.push_back(
                MInstr::make_unary(MOp::TEST, R(MReg::RAX), R(MReg::RAX)));
            seq.push_back(
                MInstr::make_jcc(MCond::E, lcont)); // RAX==0 -> no swap
            /* El OSR-entry del C2 es VM_ABI: su prologue hace
             * `mov rbx, <arg0>` esperando ProcessVM* en el registro del 1er
             * argumento (A0 = RCX win / RDI sysv).  El epilogue del C1
             * restaura RBX al valor del caller (pop rbx) -> hay que pasar
             * proc por A0 ANTES del epilogue.  A0 es caller-saved y NO esta
             * en callee_saved -> sobrevive el epilogue (igual que RAX). */
            seq.push_back(MInstr::make_unary(MOp::MOV, R(A0), R(MReg::RBX)));
            lw.emit_epilogue(seq); // rsp -> ret_addr; RAX + A0 intactos
            {
                MInstr j;
                j.op = MOp::JMP;
                j.src1 = R(MReg::RAX);
                seq.push_back(j);
            }
            seq.push_back(MInstr::make_label_def(lcont));
            /* --- ruta sin swap (RAX==0): continuar el loop C1 normal. --- */
            if (adjust)
                seq.push_back(MInstr::make_unary(
                    MOp::ADD, R(MReg::RSP),
                    MOperand::make_imm32(static_cast<int32_t>(adjust))));
            for (size_t i = cs.size(); i-- > 0;)
                seq.push_back(MInstr::make_unary(
                    MOp::POP, R(static_cast<MReg>(cs[i])), {}));
            seq.push_back(MInstr::make_label_def(lskip));
            outv.insert(outv.end() - 1, seq.begin(), seq.end());
        }
        pf.blocks[b].instrs = std::move(outv);
    }

    /* --- OSR 2b: APPEND del bloque OSR-entry (C2, el 2o punto de entrada
     * a mitad del loop).  Monta el frame normal, carga el live-in del
     * header desde proc->osr_buffer[vid] a la ubicacion fisica de cada vid,
     * y salta al MBlock del header.  R10/R11 (scratch, no asignables) como
     * base/temp -> nunca colisionan con la ubicacion fisica de un vid. */
    if (osr != nullptr && ivs != nullptr && !first_gi.empty() &&
        osr->header_block != MBLOCK_INVALID &&
        static_cast<size_t>(osr->header_block) < NB) {
        const MBlockId header = osr->header_block;
        const uint32_t header_pos = 2u * first_gi[header];
        const uint32_t NVI = static_cast<uint32_t>(ivs->intervals.size());
        const uint32_t ir_n = vf.ir_value_count;

        /* (0) Recolectar el live-in del header (covers(header_pos)) y, si hay
         * red de seguridad (required_captures), VERIFICAR que todo vid este
         * en el conjunto capturado por el C1.  Si alguno NO esta -> ABORTAR
         * (no emitir el OSR-entry) -> el C2 no se registra -> sin swap -> el
         * C1 continua.  Asi un C2 optimizado que necesite un valor no
         * capturado por el C1 degrada a "sin speedup", nunca a corrupcion. */
        std::vector<uint32_t> live_in;
        bool mismatch = false;
        for (uint32_t v = 0; v < NVI; ++v) {
            const LiveInterval &lv = ivs->intervals[v];
            if (!lv.covers(header_pos)) continue;
            if (v >= ir_n || v >= VESTA_OSR_BUFFER_N) continue;
            if (alloc.timeline.lookup(v, codegen::LinearPos{header_pos})
                    .is_none())
                continue; // sin ubicacion
            if (osr->required_captures != nullptr) {
                const auto &req = *osr->required_captures;
                bool found = false;
                for (uint32_t cv : req)
                    if (cv == v) {
                        found = true;
                        break;
                    }
                if (!found) {
                    mismatch = true;
                    break;
                }
            }
            live_in.push_back(v);
        }
        if (mismatch) {
            osr->osr_entry_valid = false; // fallback seguro: no swap
        } else {
            const MLabelId lbl = pf.new_label();
            auto R = [](MReg r) { return MOperand::make_reg(r, 8); };
            const MReg base = lw.scr0(); // R10 (no asignable)
            const MReg tmp = lw.scr1();  // R11 (no asignable)
            MBlock entryb;
            entryb.label_id = lbl;
            entryb.succ_a = header; // metadata (el jmp usa el label)
            entryb.succ_b = MBLOCK_INVALID;
            std::vector<MInstr> ob;
            /* (a) Prologue IDENTICO al de la entry 0 (mismo frame). */
            lw.emit_prologue(ob);
            /* (b) base = proc->osr_buffer (via RBX = ProcessVM*). */
            ob.push_back(MInstr::make_unary(
                MOp::MOV, R(base),
                MOperand::make_mem(MReg::RBX, VESTA_PROC_OSR_BUFFER_OFFSET)));
            /* (c) cargar cada live-in vid del buffer a su reg/slot. */
            for (uint32_t v : live_in) {
                const MOperand srcmem =
                    MOperand::make_mem(base, static_cast<int32_t>(v * 8u));
                const codegen::ValueLocation vl =
                    alloc.timeline.lookup(v, codegen::LinearPos{header_pos});
                if (vl.is_register()) {
                    ob.push_back(MInstr::make_unary(
                        MOp::MOV,
                        MOperand::make_reg(static_cast<MReg>(vl.register_id()),
                                           8),
                        srcmem));
                } else { /* memoria (garantizado por el filtro de arriba). */
                    ob.push_back(MInstr::make_unary(MOp::MOV, R(tmp), srcmem));
                    ob.push_back(MInstr::make_unary(
                        MOp::MOV,
                        MOperand::make_mem(MReg::RBP,
                                           lw.slot_off(vl.stack_slot())),
                        R(tmp)));
                }
            }
            /* (d) saltar al header (reanuda el loop a mitad). */
            ob.push_back(MInstr::make_jmp(pf.blocks[header].label_id));
            entryb.instrs = std::move(ob);
            pf.blocks.push_back(std::move(entryb));
            osr->osr_entry_label = lbl;
            osr->osr_entry_valid = true;
        }
    }

    /* --- Peephole final: eliminar `mov r64, r64` con el MISMO registro
     * (no-ops puros del two-address legalization: `mov pdst, rs1` cuando
     * pdst==rs1).  En un loop apretado (p.ej. un C2 con inline agresivo)
     * estos consumen ancho de banda de DECODE aunque el renamer los elimine.
     * SOLO width 8: un `mov e_x, e_x` de 32 bits zero-extiende los 64 bits
     * (NO es no-op) y se conserva.  Cero riesgo: un self-mov de 64 bits es
     * semanticamente identico a su ausencia. */
    for (auto &blk : pf.blocks) {
        std::vector<MInstr> cleaned;
        cleaned.reserve(blk.instrs.size());
        for (MInstr &mi : blk.instrs) {
            if (mi.op == MOp::MOV && mi.dst.kind == MOperandKind::REG &&
                mi.src1.kind == MOperandKind::REG &&
                mi.dst.reg == mi.src1.reg && mi.dst.width == 8 &&
                mi.src1.width == 8) {
                continue; // self-mov de 64 bits -> descartar
            }
            cleaned.push_back(std::move(mi));
        }
        blk.instrs = std::move(cleaned);
    }

    pf.stackmaps = std::move(lw.stackmaps); // commit 6
    return pf;
}
} // namespace jit
