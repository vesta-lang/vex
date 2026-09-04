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
 * @file aot/aot_lower.cpp
 * @brief  AOT.2 -- impl del pase de re-bajada LIBC_MAPPED -> CALL libc.
 */

#include "aot/aot_lower.h"
#include "ir/ssa_ir.h"

// Cada area de bajada, en su fichero.  Include RELATIVO: la regla de
// estructura prohibe meter src/ en el include-path global.
#include "lower/statics.h"

#include <unordered_map>

namespace aot {

void aot_lower_runtime(ir::IrModule &mod, const AotLowerConfig &cfg) {
    /* Los huecos globales que este pase crea para los campos estaticos.
     *
     * UNO por nombre y para TODO el modulo, no por funcion: un campo estatico
     * es uno solo en el programa, y quien lo escribe y quien lo lee casi nunca
     * son la misma funcion.  Con un hueco por funcion no habria ningun error --
     * cada una escribiria y leeria el suyo, tan campante -- y el programa
     * devolveria CERO donde debia devolver la suma. */
    std::unordered_map<std::string, uint64_t> static_slots;
    const auto slot_for = [&](const std::string &name) -> uint64_t {
        auto it = static_slots.find(name);
        if (it != static_slots.end()) return it->second;
        std::vector<uint8_t> zeros(8, 0);
        const uint64_t idx =
            static_cast<uint64_t>(mod.static_data.push_back(std::move(zeros)));
        auto &meta = mod.static_data.meta_at(idx);
        /* Sin deduplicar: todos los huecos empiezan a cero, y juntarlos por
         * tener los mismos bytes iniciales haria que dos campos distintos
         * compartieran almacenamiento.  Tampoco daria un error. */
        meta.flags |= ir::IrModule::SD_FLAG_NON_DEDUP;
        /* Y lo mismo entre modulos, donde ni siquiera se ven: el que declara el
         * campo y el que solo lo usa tienen que acabar en el mismo sitio al
         * juntarlos, y lo que los une es el nombre. */
        meta.shared_key = name;
        /* Es MUTABLE, asi que va a la seccion de datos y no a la de solo
         * lectura: escribir ahi revienta el proceso.  Sin esto el codegen ni
         * siquiera lo reconoce como dato -- lo toma por la direccion de una
         * funcion y falla al resolverla. */
        meta.section_name = ".data";
        static_slots.emplace(name, idx);
        return idx;
    };

    for (auto &fn : mod.functions) {
        // Mapa vid -> op que lo define (para detectar raw_free de un ALLOCA:
        // memoria de pila que NO debe liberarse -> evita free de un puntero
        // colgante / crash nativo).
        std::unordered_map<ir::IrValueId, ir::IrOp> def_op;
        for (auto &bb : fn.blocks)
            for (auto &in : bb.instrs)
                if (in.dst != ir::IR_NO_VALUE) def_op[in.dst] = in.op;

        /* Si se llego a bajar algun campo estatico.  Solo entonces puede haber
         * quedado huerfana la busqueda de su clase, y solo entonces hay que ir
         * a buscarla: sin esto, la limpieza recorreria el intermedio de TODAS
         * las funciones de TODOS los programas por un caso que casi nunca se
         * da. */
        bool lowered_static = false;

        for (auto &bb : fn.blocks) {
            /* Se construye una lista NUEVA en vez de tocar la de dentro.
             *
             * Hasta ahora este pase solo podia cambiar una instruccion por
             * otra -- `raw_alloc` por una llamada --, y eso basta cuando la
             * cuenta no cambia.  Un campo estatico no cabe en una: hay que
             * decir donde vive y luego leerlo.  Insertar sobre la lista que se
             * esta recorriendo invalida el recorrido, asi que se copia lo que
             * se conserva y se anade lo que se genera. */
            std::vector<ir::IrInstr> out;
            out.reserve(bb.instrs.size());
            for (auto &in : bb.instrs) {
                switch (in.op) {
                case ir::IrOp::RAW_ALLOC:
                    // %dst = raw_alloc.ptr %size  ->  %dst = call
                    // <alloc>(%size) <alloc> = simbolo externo (convencion
                    // "malloc"), lo resuelve el linker (libc, kernel o
                    // override).
                    in.op = ir::IrOp::CALL;
                    in.func_name = cfg.alloc_sym;
                    break;

                case ir::IrOp::RAW_FREE: {
                    // raw_free %ptr  ->  call free(%ptr), salvo que %ptr:
                    //   (a) provenga de un ALLOCA (pila): NOP (liberar pila =
                    //       dangling/crash);
                    //   (b) sea un valor COLGANTE -- sin definicion en la fn y
                    //       que NO es un parametro.  Esto pasa cuando un pase
                    //       (scalar-replace / dead-alloc-elim) ELIMINA el
                    //       objeto pero deja su `raw_free` referenciando un SSA
                    //       value ya inexistente.  El interp/JIT/PE lo toleran,
                    //       pero `free()` de libc aborta ("invalid pointer",
                    //       visto en callvirt_hot via gcc).  NOPearlo es
                    //       correcto: el objeto ya no existe, no hay nada que
                    //       liberar.
                    bool nop = in.operands.empty();
                    if (!in.operands.empty()) {
                        const ir::IrValueId p = in.operands[0];
                        auto it = def_op.find(p);
                        if (it != def_op.end()) {
                            if (it->second == ir::IrOp::ALLOCA) nop = true;
                        } else {
                            // sin def: param (heap legitimo pasado) -> free;
                            // colgante (objeto eliminado) -> NOP.
                            bool is_param = false;
                            for (ir::IrValueId pv : fn.params)
                                if (pv == p) {
                                    is_param = true;
                                    break;
                                }
                            if (!is_param) nop = true;
                        }
                    }
                    if (nop) {
                        in.op = ir::IrOp::NOP;
                        in.operands.clear();
                        in.func_name.clear();
                        in.dst = ir::IR_NO_VALUE;
                    } else {
                        in.op = ir::IrOp::CALL;
                        in.func_name = cfg.free_sym;
                    }
                    break;
                }

                case ir::IrOp::CALL:
                case ir::IrOp::TAILCALL:
                    // AOT.2.d: el `new` nativo emite calloc(1,size) para
                    // zero-init.  Con un @AllocatorOverride (incluido el slab
                    // vx_mem por defecto) lo reescribimos a alloc_sym(size)
                    // -- 1 arg, descartando el `count` (=1) -> el `new` usa el
                    // allocator override sin arrastrar calloc de libc.  El
                    // override debe zerificar (convencion kzalloc) para
                    // preservar el cero-init de los campos no escritos.  Cubre
                    // CALL y TAILCALL (un `new` con ctor trivial -> el
                    // optimizador promueve calloc a tail-call).
                    if (cfg.has_alloc_override && in.func_name == "calloc" &&
                        in.operands.size() == 2) {
                        in.func_name = cfg.alloc_sym;
                        const ir::IrValueId sz =
                            in.operands[1]; // (count, SIZE)
                        in.operands.clear();
                        in.operands.push_back(sz);
                    }
                    break;

                case ir::IrOp::CALLN:
                    // ffi_call: CALLN "__callni__:" con
                    // operands=[fn_ptr,args..]
                    // -> CALLIND (llamada INDIRECTA nativa que vreg_select baja
                    // a `call reg`): func_ptr = operands[0], args = el resto.
                    // El resto de CALLN (extern "lib" fn) pasa sin cambios.
                    if (in.func_name.rfind("__callni__:", 0) == 0 &&
                        !in.operands.empty()) {
                        in.op = ir::IrOp::CALLIND;
                        in.func_ptr = in.operands[0];
                        in.operands.erase(in.operands.begin());
                        in.func_name.clear();
                    }
                    break;

                case ir::IrOp::DLOPEN:
                    // ffi_open: dlopen %path_addr, %path_len  ->  call
                    // __vx_dlopen(%path_addr).  La funcion Vesta (vx_ffi.vx)
                    // usa LoadLibraryA/dlopen segun @Target.  El path es una
                    // cstring NUL-terminada (el frontend la NUL-termina).  Se
                    // descarta %path_len (las APIs nativas leen hasta el NUL).
                    in.op = ir::IrOp::CALL;
                    in.func_name = cfg.dlopen_sym;
                    if (!in.operands.empty())
                        in.operands.resize(1); // [path_addr]
                    break;

                case ir::IrOp::DLSYM:
                    // ffi_sym: dlsym %handle, %name_addr, %name_len  ->  call
                    // __vx_dlsym(%handle, %name_addr).  Descarta %name_len.
                    in.op = ir::IrOp::CALL;
                    in.func_name = cfg.dlsym_sym;
                    if (in.operands.size() > 2)
                        in.operands.resize(2); // [handle, name_addr]
                    break;

                case ir::IrOp::PANIC:
                    // panic(msg,len) -> call <panic>(...).  Con un
                    // @PanicHandler (panic_takes_msg) se le pasa
                    // (msg_addr, len); sin el (default abort) se
                    // descarta el mensaje (abort no toma argumentos).
                    in.op = ir::IrOp::CALL;
                    in.func_name = cfg.panic_sym;
                    if (!cfg.panic_takes_msg) in.operands.clear();
                    in.dst = ir::IR_NO_VALUE;
                    break;

                default:
                    /* Lo que necesita MAS de una instruccion se baja en su
                     * propio fichero, no aqui.
                     *
                     * Este switch resuelve lo que es una op por otra -- una
                     * reserva por una llamada --, y ahi cabe.  Un campo
                     * estatico, una cadena o un despacho virtual no caben en
                     * una sola, y meterlos aqui convertiria este fichero en el
                     * sitio donde acaba TODA la bajada del camino nativo.  Se
                     * pregunta a cada modulo si le toca; el que sepa, baja. */
                    if (lower_static_field(fn, in, out, slot_for)) {
                        lowered_static = true;
                        continue;
                    }
                    break;
                }
                out.push_back(std::move(in));
            }
            bb.instrs.swap(out);
        }

        // Cada area limpia lo suyo, igual que lo baja.
        if (lowered_static) clean_after_static_lowering(fn);
    }
}

} // namespace aot
