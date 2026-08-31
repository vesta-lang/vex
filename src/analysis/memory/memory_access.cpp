/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file memory_access.cpp
 * @brief Implementacion del vocabulario UNICO de acceso a memoria.  Un solo
 *        switch semantico LOAD/STORE/GETFIELD/ARRAY_x/MEMCPY que consumen todos
 *        los pases; memcpy NO es opaco (footprint dst+src conocido).
 */
#include "analysis/memory/memory_access.h"

#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include "ir/ssa_ir.h"

namespace analysis {

using effects::AbstractLoc;

int32_t memory_access_size(ir::IrType t) {
    /* Este era el sitio que el resto del arbol citaba como "la unica verdad
     * IrType->bytes" (lo dice el adaptador de tipo de rbank), pero seguia
     * llevando su propia tabla, asi que la unica verdad podia separarse de las
     * demas sin que nada avisara.  Ahora pregunta al vocabulario: lo que aqui
     * queda es el NOMBRE con el que la capa de memoria llama a ese eje. */
    return static_cast<int32_t>(ir::type_access_bytes(t));
}

MemoryAccessKind memory_access_kind(ir::IrOp op) {
    using Op = ir::IrOp;
    MemoryAccessKind k;
    switch (op) {
    // --- Solo leen ---
    case Op::LOAD:
    case Op::GETFIELD:
    case Op::ARRAY_LOAD:
    case Op::ARRAY_LEN: k.touches = k.is_load = true; break;
    // --- Solo escriben ---
    case Op::STORE:
    case Op::SETFIELD:
    case Op::ARRAY_STORE:
    case Op::GCWB_IR:
    case Op::MEMSET:
    case Op::VEC_ACC_ZERO:
    case Op::VEC_ACC_STORE: k.touches = k.is_store = true; break;
    // --- Leen y escriben ---
    case Op::MEMCPY:
    // Las vectoriales escriben su destino y leen sus fuentes.  Estan aqui
    // porque ESCRIBIR era justo lo que otros sitios les negaban.
    case Op::VEC_UNOP:
    case Op::VEC_BINOP:
    case Op::VEC_BINOP_S:
    case Op::VEC_FMA:
    case Op::VEC_FMA_S:
    case Op::VEC_ACC_ADD:
    case Op::VEC_ACC_FMA:
    case Op::VEC_ACC_COMBINE: k.touches = k.is_load = k.is_store = true; break;
    // --- No toca memoria ---
    // VEC_BCAST difunde un ESCALAR a un registro vectorial: no hay acceso.
    default: break;
    }
    return k;
}

int32_t memory_access_size_bytes(int32_t raw) {
    // Escalar (1/2/4/8) o vectorial (16/32/64: XMM/YMM/ZMM).  Otro -> 0 (rango
    // no exacto): NUNCA sub-estimar (un vector de 32 B como 8 perderia el
    // solapamiento con offsets 8..31 -> dependencia de memoria perdida).
    switch (raw) {
    case 1:
    case 2:
    case 4:
    case 8:
    case 16:
    case 32:
    case 64: return raw;
    default: return 0;
    }
}

namespace {
AbstractLoc unknown_loc() {
    return {AbstractLoc::Kind::Unknown, effects::LOC_GENERIC, 0, 0};
}
// Localizacion de @p ptr con ancho @p width MAS un offset EXTRA constante (para
// accesos base+disp: acumuladores VEC_ACC en acc_slot+aidx*width, datos
// a+disp). Solo se suma el offset si la loc base es PRECISA (width>0); si es
// whole-root o Unknown, el offset no es representable -> se deja como esta
// (conservador).
AbstractLoc loc_at(const PointsTo &pt, ir::IrValueId ptr, int32_t width,
                   int64_t extra_off) {
    AbstractLoc l = loc_of(pt, ptr, width);
    if (l.width > 0) l.off += extra_off;
    return l;
}
} // namespace

MemoryAccess memory_access(const ir::IrInstr &ins, const PointsTo &pt) {
    using Op = ir::IrOp;
    MemoryAccess a;
    const auto &ops = ins.operands;
    const int32_t w = memory_access_size(ins.type);
    // Ancho VECTORIAL (16/32/64) para los ops VEC_*: vive en imm&0xFF (bytes).
    const int32_t vw =
        memory_access_size_bytes(static_cast<int32_t>(ins.imm & 0xFF));

    switch (ins.op) {
    // --- Lecturas con direccion precisa (offset+ancho) ---
    case Op::LOAD:
        if (!ops.empty()) {
            a.touches = a.is_load = true;
            a.reads.push_back(loc_of(pt, ops[0], w));
        }
        return a;
    // --- Lecturas de cabecera de objeto (whole-object) ---
    case Op::GETFIELD:
    case Op::ARRAY_LOAD:
    case Op::ARRAY_LEN:
        if (!ops.empty()) {
            a.touches = a.is_load = true;
            a.reads.push_back(loc_of(pt, ops[0], 0));
        }
        return a;
    // --- Escrituras con direccion precisa ---
    case Op::STORE:
        if (ops.size() >= 2) {
            a.touches = a.is_store = true;
            a.writes.push_back(loc_of(pt, ops[1], w));
        }
        return a;
    // --- Escrituras a campo/elemento (whole-object) ---
    case Op::SETFIELD:
    case Op::ARRAY_STORE:
    case Op::GCWB_IR:
        if (!ops.empty()) {
            a.touches = a.is_store = true;
            a.writes.push_back(loc_of(pt, ops[0], 0));
        }
        return a;
    // --- MEMCPY: NO es opaco.  dst=ops[0] (write), src=ops[1] (read).  El
    //     offset exacto no se conoce -> whole-root (disjuncion por RAiZ). ---
    case Op::MEMCPY:
        if (ops.size() >= 3) {
            a.touches = a.is_load = a.is_store = true;
            a.reads.push_back(loc_of(pt, ops[1], 0));  // src
            a.writes.push_back(loc_of(pt, ops[0], 0)); // dst
        } else {
            a.touches = a.opaque = a.is_store = true;
            a.writes.push_back(unknown_loc());
        }
        return a;
    /* --- MEMSET: escribe dst=ops[0] y NO lee memoria (ops[1] es el valor, un
     *     escalar; ops[2] la longitud).  Mismo whole-root que MEMCPY.
     *
     *     Faltaba, y el modelo de efectos lo enruta AQUI dando por hecho que
     *     esta modelado, asi que caia en el `default` y contestaba "no toca
     *     memoria".  Consecuencia: una funcion cuyo unico trabajo es rellenar
     *     un buffer del llamante -- el bucle `p[i] = 0` que el pase de memoria
     *     masiva sube a MEMSET -- salia con los contratos `pure` y `readonly`,
     *     y ademas con el analisis marcado como COMPLETO: no decia "no lo se",
     *     afirmaba que no escribe nada.  Es el mismo fallo que el comentario
     *     de ir_effects.cpp da por cerrado para las ops vectoriales; MEMSET se
     *     quedo fuera. --- */
    case Op::MEMSET:
        if (ops.size() >= 3) {
            a.touches = a.is_store = true;
            a.writes.push_back(loc_of(pt, ops[0], 0)); // dst
        } else {
            a.touches = a.opaque = a.is_store = true;
            a.writes.push_back(unknown_loc());
        }
        return a;

    // --- Ops VECTORIALES sobre PUNTEROS (SIMD 16/32/64 B): footprint PRECISO.
    //     El ancho (vw) es 16/32/64 de imm&0xFF; los operandos son punteros a
    //     memoria (base+i*esz).  NUNCA sub-estimar el rango vectorial. ---
    case Op::VEC_UNOP: // {dst, src}: escribe dst, lee src
        if (ops.size() >= 2) {
            a.touches = a.is_load = a.is_store = true;
            a.writes.push_back(loc_of(pt, ops[0], vw));
            a.reads.push_back(loc_of(pt, ops[1], vw));
        }
        return a;
    case Op::VEC_BINOP: // {dst, a, b}: escribe dst, lee a y b
        if (ops.size() >= 3) {
            a.touches = a.is_load = a.is_store = true;
            a.writes.push_back(loc_of(pt, ops[0], vw));
            a.reads.push_back(loc_of(pt, ops[1], vw));
            a.reads.push_back(loc_of(pt, ops[2], vw));
        }
        return a;
    case Op::VEC_BINOP_S: // {dst, a, ESCALAR}: escribe dst, lee a (op2 =
                          // escalar)
        if (ops.size() >= 2) {
            a.touches = a.is_load = a.is_store = true;
            a.writes.push_back(loc_of(pt, ops[0], vw));
            a.reads.push_back(loc_of(pt, ops[1], vw));
        }
        return a;
    /* VEC_FMA_S: {c, a, ESCALAR} -> c += a*escalar.  Faltaba: al no tener caso
     * caia en el `default` y salia como "no toca memoria", cuando lee y escribe
     * su acumulador.  A diferencia de MEMSET esto no llego a ser incorrecto:
     * el modelo de efectos NO la enruta aqui, asi que le aplica su efecto
     * maximo y ademas deja constancia de la laguna.  Modelarla la quita de ese
     * saco. */
    case Op::VEC_FMA_S:
        if (ops.size() >= 2) {
            a.touches = a.is_load = a.is_store = true;
            a.writes.push_back(loc_of(pt, ops[0], vw)); // c (acumulador)
            a.reads.push_back(loc_of(pt, ops[0], vw));  // c se lee para sumar
            a.reads.push_back(loc_of(pt, ops[1], vw));  // a
        }
        return a;
    case Op::VEC_FMA: // {c, d, a, b}: c = a*b + d -> escribe c, lee d/a/b
        if (ops.size() >= 4) {
            a.touches = a.is_load = a.is_store = true;
            a.writes.push_back(loc_of(pt, ops[0], vw));
            a.reads.push_back(loc_of(pt, ops[1], vw));
            a.reads.push_back(loc_of(pt, ops[2], vw));
            a.reads.push_back(loc_of(pt, ops[3], vw));
        }
        return a;
    // --- VEC_BCAST: broadcast de un ESCALAR a un registro vectorial -> NO toca
    //     memoria (el operando es un valor escalar, el destino es un reg). ---
    case Op::VEC_BCAST:
        return a; // touches = false

    // --- VEC_ACC_* (acumuladores de reduccion): acc_slot (ops[0]) es un ALLOCA
    //     de U*width bytes; imm = ancho(0-7)|acc_idx(8-11)|src_idx(12-15)|
    //     disp(16-31).  acc[k] esta en acc_slot + k*width; los datos se leen a
    //     ptr+disp.  Modelado PRECISO -> las escrituras van al scratch LOCAL
    //     (Stack#acc_slot), disjunto de la memoria del caller. ---
    case Op::VEC_ACC_ZERO: // {acc_slot}: zero acc[aidx]
        if (!ops.empty()) {
            const uint64_t im = static_cast<uint64_t>(ins.imm);
            const int32_t aw = memory_access_size_bytes(int32_t(im & 0xFF));
            const int64_t aidx = int64_t((im >> 8) & 0xF);
            a.touches = a.is_store = true;
            a.writes.push_back(loc_at(pt, ops[0], aw, aidx * aw));
        }
        return a;
    case Op::VEC_ACC_ADD: // {acc_slot, a}: acc[aidx] += a[disp]
    case Op::VEC_ACC_FMA: // {acc_slot, a, b}: acc[aidx] += a[disp]*b[disp]
        if (!ops.empty()) {
            const uint64_t im = static_cast<uint64_t>(ins.imm);
            const int32_t aw = memory_access_size_bytes(int32_t(im & 0xFF));
            const int64_t aidx = int64_t((im >> 8) & 0xF);
            const int64_t disp = int64_t((im >> 16) & 0xFFFF);
            a.touches = a.is_load = a.is_store = true;
            const AbstractLoc accl = loc_at(pt, ops[0], aw, aidx * aw);
            a.reads.push_back(accl);  // acc read-modify
            a.writes.push_back(accl); // acc write
            if (ops.size() >= 2)
                a.reads.push_back(loc_at(pt, ops[1], aw, disp));
            if (ins.op == Op::VEC_ACC_FMA && ops.size() >= 3)
                a.reads.push_back(loc_at(pt, ops[2], aw, disp));
        }
        return a;
    case Op::VEC_ACC_COMBINE: // {acc_slot}: acc[0] += acc[src_idx]
        if (!ops.empty()) {
            const uint64_t im = static_cast<uint64_t>(ins.imm);
            const int32_t aw = memory_access_size_bytes(int32_t(im & 0xFF));
            const int64_t sidx = int64_t((im >> 12) & 0xF);
            a.touches = a.is_load = a.is_store = true;
            a.reads.push_back(loc_at(pt, ops[0], aw, sidx * aw)); // fuente
            const AbstractLoc dst0 = loc_at(pt, ops[0], aw, 0);   // acc[0]
            a.reads.push_back(dst0);
            a.writes.push_back(dst0);
        }
        return a;
    case Op::VEC_ACC_STORE: // {acc_slot}: vuelca el acc register-resident a
                            // acc[0]
        if (!ops.empty()) {
            const uint64_t im = static_cast<uint64_t>(ins.imm);
            const int32_t aw = memory_access_size_bytes(int32_t(im & 0xFF));
            a.touches = a.is_store = true;
            a.writes.push_back(loc_at(pt, ops[0], aw, 0));
        }
        return a;

    default: return a; // no es un acceso a memoria localizable
    }
}

} // namespace analysis
