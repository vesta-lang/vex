/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/scopes.cpp
 * @brief Que nombre se refiere a que valor, en cada punto del programa.
 *
 * El bajado avanza por el fuente llevando una pila de ambitos: entrar en un
 * bloque apila, salir desapila, y un nombre siempre se resuelve al mas cercano.
 * Eso es lo facil.
 *
 * Lo que no lo es: en SSA un nombre no tiene UN valor, tiene uno por cada punto
 * del programa -- reasignar no cambia el valor, crea otro --, asi que el ambito
 * guarda cual es el vigente y hay que ACTUALIZARLO en cada escritura.  Y cuando
 * de una variable se toma la direccion, deja de vivir en un valor y pasa a
 * vivir en memoria: desde entonces leerla es una carga y escribirla un
 * almacenamiento.  Distinguir esos dos mundos es el trabajo de este fichero.
 */
#include "vx/lowering.h"
#include "util/thread_slot.h" // el estado por hilo NO va en thread_local
#include "ir/ir_type_info.h"  // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering

namespace vx {

void Lowering::push_scope() {
    scopes_.emplace_back();
}

void Lowering::pop_scope() {
    scopes_.pop_back();
}

void Lowering::bind(const std::string &name, ir::IrValueId v) {
    scopes_.back()[name] = v;
    // Debug-info (solo-LSP / dumps): si el valor SSA aun no tiene nombre de
    // fuente, etiquetarlo con el de la variable -> la pestana IR muestra "%t"
    // en vez de "%5", y el cache de modulo lo persiste para el inspector.  NO
    // sobreescribimos nombres ya puestos (params "%n", alias) para no
    // corromperlos.  Cosmetico: el optimizer/codegen indexan por ID, no por
    // nombre, y el @ir de produccion no serializa nombres -> cero efecto en
    // runtime/JIT.
    if (fn_ && v != ir::IR_NO_VALUE && v < fn_->values.size() &&
        !name.empty()) {
        std::string &vn = fn_->values[v].name;
        // new_value() rellena el nombre por defecto como "%<id>".  Solo
        // sobreescribimos ese auto-nombre (no params "%n" ni alias ya
        // nombrados) para no corromper nombres significativos.
        const bool is_default = (vn == "%" + std::to_string(fn_->values[v].id));
        if (is_default) vn = "%" + name;
    }
}

ir::IrValueId Lowering::lookup(const std::string &name) const {
    for (auto it = scopes_.rbegin(); it != scopes_.rend(); ++it) {
        auto found = it->find(name);
        if (found != it->end()) return found->second;
    }
    return ir::IR_NO_VALUE;
}

// Wrapper publico para que helpers estaticos (e.g.
// @c collect_spawn_captures_in_expr) puedan resolver un nombre en
// todos los scopes activos del lowering sin tener acceso directo a
// @c lookup (que es @c const private).  Delega a @c lookup.
ir::IrValueId Lowering::spawn_capture_resolve(const std::string &name) {
    return lookup(name);
}

void Lowering::update_scope(const std::string &name, ir::IrValueId v) {
    // Buscar de mas interno a global y actualizar in-place.  Esto evita
    // crear sombras accidentales (que pasaria si simplemente hicieramos
    // bind() sobre el scope actual en lugar del scope donde la variable
    // se declaro).
    for (auto it = scopes_.rbegin(); it != scopes_.rend(); ++it) {
        auto found = it->find(name);
        if (found != it->end()) {
            found->second = v;
            return;
        }
    }
    // Fallback: si no existe en ningun scope, registrar en el actual.
    // El type checker normalmente atrapa esto antes, pero defendemos
    // para no perder informacion en caso de un AST malformado.
    bind(name, v);
}

ir::IrValueId Lowering::read_local(const std::string &name, ir::IrType ir_ty,
                                   uint32_t source_line) {
    const ir::IrValueId v = lookup(name);
    if (v == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
    if (!address_taken_locals_.count(name)) return v;
    // Address-taken: el scope guarda la direccion de un ALLOCA;
    // emitimos un LOAD para obtener el valor actual.
    const ir::IrValueId dst = emit_load_typed(v, ir_ty, source_line);
    // Limitacion (cerrada): si el local fue marcado como host-bearing
    // (al menos un write_local le grabo un valor con is_host_ptr=true),
    // el LOAD reconstruye el bit en el SSA value resultante.  Sin esto
    // el round-trip `T* p = malloc(); ...; LOAD &p` perderia el bit y
    // el siguiente LOAD/STORE indirecto emitiria mov en vez de movh.
    if (host_bearing_locals_.count(name)) {
        fn_->values[dst].is_host_ptr = true;
    }
    return dst;
}

void Lowering::write_local(const std::string &name, ir::IrValueId v,
                           ir::IrType ir_ty, uint32_t source_line) {
    // `static T x` local: la escritura va al slot global (gdata), no al
    // scope.  Persistente entre llamadas.  Los agregados no pasan por aqui
    // (se copian campo a campo via su direccion).
    {
        auto sit = static_local_slots_.find(name);
        if (sit != static_local_slots_.end() && !sit->second.aggregate) {
            ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
            {
                ir::IrInstr is{};
                is.op = ir::IrOp::STR_LIT_ADDR;
                is.type = ir::IrType::PTR;
                is.dst = addr;
                is.imm = sit->second.slot;
                is.source_line = source_line;
                emit(current_block_, std::move(is));
                fn_->values[addr].is_host_ptr = true;
            }
            emit_store_typed(addr, v, sit->second.ld_type, source_line);
            return;
        }
    }
    if (!address_taken_locals_.count(name)) {
        update_scope(name, v);
        // Si la variable tiene slot activo en un try, ADICIONALMENTE
        // emitir STORE al slot.  El motivo: cuando ocurre un @c throw
        // dentro del body del try, el handler en el catch necesita el
        // ultimo valor de la variable, pero do_throw restaura el RSP
        // y descarta cualquier @c push del save/restore alrededor de
        // los CALLs.  Sin este STORE redundante, el catch leeria un
        // registro con un valor obsoleto o corrupto.
        auto it_slot = try_spill_slots_.find(name);
        if (it_slot != try_spill_slots_.end()) {
            // Usar el tipo real del valor para que el STORE escriba
            // exactamente N bytes y no contamine los bytes altos
            // del slot 8-byte alloca.
            ir::IrType st_ty = ir_ty;
            if (v < fn_->values.size()) {
                st_ty = fn_->values[v].type;
            }
            emit_store_typed(it_slot->second, v, st_ty, source_line);
        }
        return;
    }
    // Address-taken: emitir STORE a la direccion guardada en scope.
    const ir::IrValueId addr = lookup(name);
    if (addr == ir::IR_NO_VALUE) {
        update_scope(name, v); // fallback defensivo
        return;
    }
    emit_store_typed(addr, v, ir_ty, source_line);
    // Limitacion (cerrada): registrar host-bearing si el valor escrito
    // proviene de heap host (malloc o aritmetica derivada).  read_local
    // consulta este set para propagar is_host_ptr al LOAD del slot.
    // Ademas marcamos el SSA value del slot (addr) con pointee_is_host_ptr
    // para que el caso indirecto @c &p; *pp tambien propague is_host_ptr
    // al destino del LOAD via el ir_emitter.  Sticky por simplicidad: una
    // vez marcado, el local queda host-bearing aunque despues le asignen
    // un valor VM.  Aceptable porque en la practica los locales mantienen
    // su naturaleza a lo largo de su vida.
    if (v != ir::IR_NO_VALUE && fn_->values[v].is_host_ptr) {
        host_bearing_locals_.insert(name);
        fn_->values[addr].pointee_is_host_ptr = true;
    }
}

/**
 * @brief Guarda el contexto del padre y lo deja limpio para el hijo.
 *
 * Limpiar es parte del contrato, no un anadido: la funcion hija empieza sin
 * nombres, sin nada con la direccion tomada y sin nada que soltar.  Heredarlos
 * del padre haria que un nombre del padre se resolviera dentro del hijo, donde
 * ese valor no existe.
 *
 * @param lo El bajador cuyo contexto se guarda.
 */
Lowering::ChildFunctionScope::ChildFunctionScope(Lowering &lo)
    : lo_(lo), fn_(lo.fn_), block_(lo.current_block_),
      terminated_(lo.block_terminated_), scopes_(std::move(lo.scopes_)),
      addr_taken_(std::move(lo.address_taken_locals_)),
      host_bearing_(std::move(lo.host_bearing_locals_)),
      cleanups_(std::move(lo.cleanup_stack_)), sret_active_(lo.sret_active_),
      sret_retbuf_(lo.sret_retbuf_), sret_buf_size_(lo.sret_buf_size_),
      returns_function_(lo.current_fn_returns_function_),
      async_fut_id_(lo.async_fut_id_), is_rspawn_body_(lo.is_rspawn_body_),
      is_spawn_body_(lo.is_spawn_body_) {
    lo_.scopes_.clear();
    lo_.address_taken_locals_.clear();
    lo_.host_bearing_locals_.clear();
    lo_.cleanup_stack_.clear();
    lo_.block_terminated_ = false;
    /* Como se sale es propio de cada funcion, asi que la hija empieza sin nada
     * de eso: retornando normal.  Quien construya un cuerpo que NO sea una
     * funcion -- el de una asincrona, el de un proceso -- lo dice DESPUES de
     * construir el guarda, y solo vale mientras dure. */
    lo_.sret_active_ = false;
    lo_.sret_retbuf_ = ir::IR_NO_VALUE;
    lo_.sret_buf_size_ = 0;
    lo_.current_fn_returns_function_ = false;
    lo_.async_fut_id_ = ir::IR_NO_VALUE;
    lo_.is_rspawn_body_ = false;
    lo_.is_spawn_body_ = false;
}

/**
 * @brief Devuelve el contexto del padre tal y como estaba.
 */
Lowering::ChildFunctionScope::~ChildFunctionScope() {
    lo_.fn_ = fn_;
    lo_.current_block_ = block_;
    lo_.block_terminated_ = terminated_;
    lo_.scopes_ = std::move(scopes_);
    lo_.address_taken_locals_ = std::move(addr_taken_);
    lo_.host_bearing_locals_ = std::move(host_bearing_);
    lo_.cleanup_stack_ = std::move(cleanups_);
    lo_.sret_active_ = sret_active_;
    lo_.sret_retbuf_ = sret_retbuf_;
    lo_.sret_buf_size_ = sret_buf_size_;
    lo_.current_fn_returns_function_ = returns_function_;
    lo_.async_fut_id_ = async_fut_id_;
    lo_.is_rspawn_body_ = is_rspawn_body_;
    lo_.is_spawn_body_ = is_spawn_body_;
}

} // namespace vx
