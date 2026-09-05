/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/bundle/liveness.cpp
 * @brief Vivacidad de registros dentro y detras de un paquete.
 *
 * Ver `include/runtime/bundle/liveness.h` para el porque y las garantias.
 */

#include "runtime/bundle/liveness.h"

#include "runtime/bundle/bundle_touch_all.h"

#if VM_BUNDLES

#include "runtime/decode_instruction.h"

namespace runtime {

namespace {

/// Ningun registro resuelto: todos vivos.  Es la respuesta a "no se".
constexpr uint16_t kAllLive = 0xFFFF;

/**
 * @brief Cuantas instrucciones se miran mas alla del final del paquete.
 *
 * Ocho, y no mas, porque el matador de un temporal -- cuando existe -- esta
 * cerca: es el siguiente uso de ese registro.  Cuesta descodificar ocho
 * instrucciones UNA vez por sitio, en el camino de formacion, que es el 0,57%
 * de las ejecuciones.
 */
constexpr uint32_t kLookahead = 8;

} // namespace

void bundle_live_after(const Bundle &b, const Touch *t, uint16_t live_out,
                       uint16_t *out) {
    uint16_t live = live_out;
    for (uint32_t j = b.k; j-- > 0;) {
        if (t[j].barrier) {
            /* Una barrera lo revive TODO.  Si el paquete puede irse por ahi, lo
             * de detras no corrio y el registro puede leerse en cualquier otro
             * sitio.  Vale igual para lo que transfiere control y para lo que
             * tiene efectos de cota inferior. */
            out[j] = kAllLive;
            live = kAllLive;
            continue;
        }
        out[j] = live;
        const uint16_t kill = (uint16_t)(t[j].reg_write & ~t[j].reg_read);
        live = (uint16_t)((live & ~kill) | t[j].reg_read);
    }
}

/* RETIRADO: `bundle_split_point`, que buscaba por donde partir un paquete en
 * dos mitades independientes.
 *
 * La pregunta ya no se hace.  Repartir MEDIO paquete y esperar en el sitio daba
 * raciones de 15,9 instrucciones -- unos 47 ns -- para un traspaso entre
 * nucleos que cuesta cientos, y el perfil de hardware lo dejo sin dudas:
 * `Serializing Operations` al 100% de los ciclos y 0,755 s esperando contra
 * 0,411 s trabajando.  Ahora la unidad es el paquete ENTERO y la pregunta es
 * otra -- puede irse tal cual, y choca con lo que ya vuela? --, que se contesta
 * con `Bundle::Summary` y el marcador de `ProcessVM::ooo_inflight`.
 *
 * Se quita en vez de dejarlo apagado porque un analisis que nadie consulta no
 * envejece bien: se queda diciendo cosas de un diseno que ya no existe.  Vive
 * en el historial de git. */


uint16_t live_out_after(ProcessVM *process, uint64_t pc) {
    uint16_t live = 0;   // lo que LEE lo que viene detras
    uint16_t killed = 0; // lo que ya se piso, y por tanto no puede leerse
    for (uint32_t n = 0; n < kLookahead; ++n) {
        DecodedInstr ins;
        if (!decode_peek(process, pc, ins)) return kAllLive;
        if (ins.exec_cached == nullptr && ins.metadata != nullptr)
            ins.exec_cached = ins.metadata->exec;

        Touch t;
        if (!touch_one(ins, t)) return kAllLive; // barrera: se acaba lo que se sabe

        live |= (uint16_t)(t.reg_read & ~killed);
        killed |= (uint16_t)(t.reg_write & ~t.reg_read);
        if (killed == kAllLive) break; // ya no queda nada por resolver
        pc += ins.flags_info.size_instr;
    }
    /* Lo que ni se leyo ni se piso en la ventana sigue sin resolverse, y sin
     * resolver es VIVO. */
    return (uint16_t)(live | ~killed);
}

} // namespace runtime

#endif // VM_BUNDLES
