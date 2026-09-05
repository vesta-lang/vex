/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle/bundle_touch_all.h
 * @brief Lo que toca CADA instruccion del paquete, calculado UNA sola vez.
 *
 * POR QUE EXISTE
 * --------------
 * Tres pasos del camino de formacion querian lo mismo y cada uno lo calculaba
 * por su cuenta: el reordenador, el fusionador y la busqueda de corte para
 * repartir.  Son ~32 consultas a la tabla caliente, otras tantas a la de formas
 * y un `regs_of_form` por instruccion, TRES veces por paquete formado.
 *
 * Medido: anadir el tercero costo un 19% en el motor de paquetes -- que ni
 * reordena ni fusiona --, y la duplicacion entre los dos primeros ya estaba ahi
 * antes.
 *
 * LAS TRES VARIANTES SALEN DE UNA
 * -------------------------------
 * Lo CRUDO es el nucleo comun, y las diferencias no valen una pasada:
 *
 *   - quien REORDENA quiere la version prudente -- dar por leido lo que se
 *     escribe --, que es un `or` por instruccion, y tratar como barrera a lo
 *     que lee `rip`, que ya esta en `field_read`;
 *   - quien FUSIONA quiere lo crudo: necesita saber si el destino se PISA sin
 *     leerse, y la prudencia del otro borra justo ese dato;
 *   - quien REPARTE quiere lo crudo mas la clase de `rip`.
 *
 * LO QUE HAY QUE RESPETAR AL USARLO
 * ---------------------------------
 * Esto describe a `b.instr[i]` POR INDICE, asi que quien mueva las
 * instrucciones tiene que mover esto con ellas.  El reordenador PERMUTA el
 * paquete y el fusionador lo COMPACTA; los dos actualizan estos arrays en el
 * mismo bucle en el que tocan `instr`.
 *
 * No hacerlo no da un error: deja el analisis hablando de OTRA instruccion, y
 * entonces se fusiona o se reordena mirando dependencias que no son.  Es el
 * modo de fallo que este fichero tiene que evitar, no uno que provoque.
 */

#ifndef VESTA_RUNTIME_BUNDLE_TOUCH_ALL_H
#define VESTA_RUNTIME_BUNDLE_TOUCH_ALL_H

#include <cstdint>

#include "runtime/bundle.h"
#include "runtime/bundle/fuse_roles.h"
#include "runtime/bundle/touch.h"

#if VM_BUNDLES

namespace runtime {

/// Lo que toca cada instruccion del paquete, en paralelo a `Bundle::instr`.
struct BundleTouch {
    Touch t[BUNDLE_MAX];        ///< CRUDO: lectura y escritura separadas
    TouchKind kind[BUNDLE_MAX]; ///< movible / lee `rip` / barrera
    uint8_t role[BUNDLE_MAX];   ///< que papel puede jugar en una fusion
    uint32_t movable = 0;       ///< cuantas se pueden mover
};

/// Calcula lo de arriba para las `b.k` instrucciones.  Una pasada.
[[gnu::always_inline]] inline void bundle_touch_all(const Bundle &b,
                                                    BundleTouch &out) {
    out.movable = 0;
    for (uint32_t i = 0; i < b.k; ++i) {
        out.t[i] = Touch{};
        out.kind[i] = touch_classify(b.instr[i], out.t[i]);
        out.role[i] = fuse_role(b.instr[i]);
        out.movable += (out.kind[i] == TouchKind::Movable) ? 1u : 0u;
    }
}

/// Copia la entrada @p from de @p src a la posicion @p to de @p dst.
///
/// Lo usan el reordenador al PERMUTAR y el fusionador al COMPACTAR: si el
/// paquete se mueve y esto no, el analisis pasa a describir otra instruccion, y
/// eso no da un error -- da un reorden o una fusion mirando dependencias que no
/// son --.
[[gnu::always_inline]] inline void bundle_touch_move(BundleTouch &dst,
                                                     uint32_t to,
                                                     const BundleTouch &src,
                                                     uint32_t from) {
    dst.t[to] = src.t[from];
    dst.kind[to] = src.kind[from];
    dst.role[to] = src.role[from];
}

} // namespace runtime

#endif // VM_BUNDLES
#endif // VESTA_RUNTIME_BUNDLE_TOUCH_ALL_H
