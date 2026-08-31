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
 * @file asm_diag.cpp
 * @brief Implementacion de los diagnosticos estructurales del CFG de asm.
 */

#include "vx/asm/asm_diag.h"

#include <deque>
#include <set>
#include <unordered_set>
#include <vector>

namespace vx {

namespace {

/// Marca los bloques ALCANZABLES desde @p start siguiendo @p succs (BFS).
std::vector<bool> reachable_forward(const AsmCfg &cfg, uint32_t start) {
    std::vector<bool> seen(cfg.blocks.size(), false);
    if (cfg.blocks.empty()) return seen;
    std::deque<uint32_t> q;
    seen[start] = true;
    q.push_back(start);
    while (!q.empty()) {
        uint32_t b = q.front();
        q.pop_front();
        for (uint32_t s : cfg.blocks[b].succs)
            if (!seen[s]) {
                seen[s] = true;
                q.push_back(s);
            }
    }
    return seen;
}

/// ¿El bloque @p b es una SALIDA del bloque asm?  Es salida si retorna, si su
/// destino es indirecto/desconocido (conservador: podria salir, para NO
/// reportar un bucle falso), o si el control puede CAER FUERA del bloque asm:
/// cuando el terminador admite fallthrough (fallthrough/call/rama condicional)
/// y no hay ninguna instruccion despues (una `jnz .loop` al final cae fuera
/// cuando la condicion es falsa).
bool is_exit_block(const AsmCfg &cfg, uint32_t b) {
    const AsmBasicBlock &bb = cfg.blocks[b];
    if (bb.term == AsmTerm::Ret || bb.term == AsmTerm::Indirect ||
        bb.term == AsmTerm::Unknown)
        return true;
    /* Saltar a una funcion del MODULO es irse del bloque asm y no volver: una
     * salida, igual que el `ret`.  Sin esto, un bloque que acaba en
     * `jmp otra_funcion` no alcanzaba ninguna salida y se reportaba como bucle
     * infinito -- justo sobre codigo que si sale --.  El destino no esta aqui,
     * asi que tampoco hay arista que lo diga. */
    if (bb.term == AsmTerm::UncondJump || bb.term == AsmTerm::CondBranch) {
        const AsmInsn &t = cfg.insns[bb.last];
        if (asm_is_external_symbol(t.target)) {
            bool definida = false;
            for (const AsmInsn &in : cfg.insns) {
                for (const std::string &l : in.labels)
                    if (l == t.target) definida = true;
                if (definida) break;
            }
            if (!definida) return true;
        }
    }
    const bool fallthrough_possible =
        (bb.term == AsmTerm::Fallthrough || bb.term == AsmTerm::Call ||
         bb.term == AsmTerm::CondBranch);
    const bool at_end = (bb.last + 1 >= cfg.insns.size());
    return fallthrough_possible && at_end;
}

/// Marca los bloques que PUEDEN ALCANZAR alguna salida (BFS inverso desde las
/// salidas siguiendo @p preds).
std::vector<bool> can_reach_exit(const AsmCfg &cfg) {
    std::vector<bool> can(cfg.blocks.size(), false);
    std::deque<uint32_t> q;
    for (uint32_t b = 0; b < cfg.blocks.size(); ++b)
        if (is_exit_block(cfg, b)) {
            can[b] = true;
            q.push_back(b);
        }
    while (!q.empty()) {
        uint32_t b = q.front();
        q.pop_front();
        for (uint32_t p : cfg.blocks[b].preds)
            if (!can[p]) {
                can[p] = true;
                q.push_back(p);
            }
    }
    return can;
}

} // namespace

std::vector<AsmDiag> asm_diagnose_cfg(const AsmCfg &cfg) {
    std::vector<AsmDiag> out;
    if (cfg.blocks.empty()) return out;

    const std::vector<bool> reach = reachable_forward(cfg, 0);

    // 1) Codigo muerto: bloque no alcanzable desde la entrada.  Un solo aviso
    // por
    //    bloque, en su primera instruccion.
    for (uint32_t b = 0; b < cfg.blocks.size(); ++b) {
        if (reach[b]) continue;
        const AsmInsn &in = cfg.insns[cfg.blocks[b].first];
        AsmDiag d;
        d.severity = AsmDiagSeverity::Warning;
        d.line_no = in.line_no;
        d.code = "VXA001"; // sin args.
        out.push_back(std::move(d));
    }

    // 2) Salto a etiqueta no definida en el bloque.
    for (const AsmInsn &in : cfg.insns) {
        if ((in.term == AsmTerm::UncondJump ||
             in.term == AsmTerm::CondBranch) &&
            !in.target.empty()) {
            bool found = false;
            for (const AsmInsn &d : cfg.insns)
                for (const std::string &l : d.labels)
                    if (l == in.target) {
                        found = true;
                        break;
                    }
            /* Que no este en el bloque no basta para avisar: en Vesta un
             * `jmp`/`jCC` puede ir a una funcion del MODULO, que resuelve el
             * enlazador.  Avisar de eso era un falso positivo sobre codigo
             * correcto -- y el aviso apuntaba justo a la linea buena --.  Solo
             * es un error si el nombre no puede venir de fuera, que es lo que
             * pasa con una etiqueta local (`.algo`) sin definir. */
            if (!found && !asm_is_external_symbol(in.target)) {
                AsmDiag d;
                d.severity = AsmDiagSeverity::Warning;
                d.line_no = in.line_no;
                d.code = "VXA002";
                d.args = {in.target}; // {0} = etiqueta destino.
                out.push_back(std::move(d));
            }
        }
    }

    // 3) Bucle sin salida: bloque alcanzable desde la entrada que NO puede
    // llegar
    //    a ninguna salida.  Reportamos una vez por region (el bloque de menor
    //    indice del grupo alcanzable de bloques sin salida).
    const std::vector<bool> can = can_reach_exit(cfg);
    bool reported_loop = false;
    for (uint32_t b = 0; b < cfg.blocks.size(); ++b) {
        if (reach[b] && !can[b]) {
            if (!reported_loop) {
                const AsmInsn &in = cfg.insns[cfg.blocks[b].first];
                AsmDiag d;
                d.severity = AsmDiagSeverity::Warning;
                d.line_no = in.line_no;
                d.code = "VXA003"; // sin args.
                out.push_back(std::move(d));
                reported_loop = true;
            }
        }
    }

    return out;
}

std::vector<AsmDiag> asm_diagnose(instr_db::Isa isa, const std::string &body) {
    return asm_diagnose_cfg(build_asm_cfg(isa, body));
}

std::vector<AsmDiag>
asm_diagnose_uninit(const AsmCfg &cfg, instr_db::Isa isa,
                    const std::vector<std::string> &defined_in,
                    uint32_t ua_id) {
    std::vector<AsmDiag> out;
    const uint32_t nb = static_cast<uint32_t>(cfg.blocks.size());
    if (nb == 0) return out;

    // Token especial que modela el registro de flags (RFLAGS/NZCV) como un
    // unico valor.  Solo tiene sentido en x86 y arm64 (RISC-V no tiene flags).
    static const std::string FLAGS = "$flags";
    const bool has_flags =
        (isa == instr_db::Isa::X86 || isa == instr_db::Isa::ARM64);

    // Semantica (lecturas/escrituras/modelada) por instruccion, cacheada.
    std::vector<instr_db::AsmInsnSem> sem(cfg.insns.size());
    // Lectura/escritura de flags por instruccion (x86/arm64).
    std::vector<bool> flag_read(cfg.insns.size(), false);
    std::vector<bool> flag_write(cfg.insns.size(), false);
    // Universo = registros canonicos que APARECEN (solo reportamos lecturas).
    std::set<std::string> universe;
    for (size_t i = 0; i < cfg.insns.size(); ++i) {
        sem[i] = instr_db::asm_insn_sem(isa, cfg.insns[i].text, ua_id);
        // Un operando que no es un registro reconocido (una const comptime aun
        // sin sustituir, una etiqueta, etc.) puede llegar con canonico vacio:
        // no es un registro, se ignora.
        for (const std::string &r : sem[i].reads)
            if (!r.empty()) universe.insert(r);
        for (const std::string &r : sem[i].writes)
            if (!r.empty()) universe.insert(r);
        if (has_flags) {
            /* Leer una bandera solo es sospechoso si es de las que deja una
             * COMPARACION.  Las demas no se ponen en el bloque ni tienen por
             * que: la de direccion vale cero al entrar por convencion de
             * llamada -- y las instrucciones de cadena la leen SIEMPRE, para
             * saber si avanzan o retroceden --, y las de modo del procesador
             * vienen de fuera por definicion.
             *
             * Sin esta distincion, un `rep movsb` avisaba de "banderas leidas
             * sin comparacion previa" y el aviso tumbaba su elevacion: la
             * instruccion pasaba a modelarse por la forma sin prefijo, que no
             * sabe del contador, y la variable ligada a `rcx` se borraba por
             * muerta.  La base distingue las banderas una por una; quien
             * preguntaba las juntaba todas en un bit. */
            bool lee_condicion = sem[i].reads_flags;
            if (sem[i].reads_flags && sem[i].form_id >= 0) {
                std::vector<std::string> lee_n, escribe_n;
                if (instr_db::flag_names_of(isa, sem[i].form_id, lee_n,
                                            escribe_n)) {
                    lee_condicion = false;
                    for (const std::string &f : lee_n)
                        if (f == "af" || f == "cf" || f == "of" || f == "pf" ||
                            f == "sf" || f == "zf") {
                            lee_condicion = true;
                            break;
                        }
                }
            }
            // Lee flags: una rama condicional (jCC / b.CC), o un consumidor de
            // flags que la DB modela (adc/sbb/cmovCC/setCC -> operando FLAGS).
            flag_read[i] =
                (cfg.insns[i].term == AsmTerm::CondBranch) || lee_condicion;
            // Escribe flags: cmp/add/sub/test/... (la DB los modela con un
            // operando FLAGS de escritura).
            flag_write[i] = sem[i].writes_flags;
            if (flag_read[i] || flag_write[i]) universe.insert(FLAGS);
        }
    }
    if (universe.empty()) return out;

    using RegSet = std::unordered_set<std::string>;
    const RegSet full(universe.begin(), universe.end());
    RegSet entry_undef =
        full; // a la entrada, todo lo no pre-definido esta indefinido.
    for (const std::string &d : defined_in)
        entry_undef.erase(d);
    // rsp/rbp (puntero de pila / marco) estan SIEMPRE vivos por el ABI: leerlos
    // NO es "sin inicializar" (VXA004 falso positivo).  Manipular la pila desde
    // el asm es valido (mov rax,rsp / push / sub rsp) -> rsp/rbp pre-definidos.
    entry_undef.erase("rsp");
    entry_undef.erase("rbp");

    // undef_in/undef_out por bloque.  Meet = interseccion (must-undefined en
    // TODOS los preds).  Inicializamos los no-entrada al TOP (full) para el
    // punto fijo.
    std::vector<RegSet> undef_in(nb), undef_out(nb, full);
    for (uint32_t b = 0; b < nb; ++b)
        undef_in[b] = full;
    undef_in[0] = entry_undef;

    // Aplica el efecto de la instruccion @p i sobre el conjunto "indefinido"
    // @p cur.  Las ramas/saltos/ret NO definen registros GP (aunque no esten en
    // la DB de coste) -> no tocan el conjunto.  Un @c call clobbera los
    // caller-saved (conservador: vacia).  Una instruccion no-modelada que NO es
    // control de flujo pudo definir cualquier cosa -> vacia.  Una modelada
    // borra sus escrituras.
    auto apply_defs = [&](uint32_t i, RegSet &cur) {
        switch (cfg.insns[i].term) {
        case AsmTerm::UncondJump:
        case AsmTerm::CondBranch:
        case AsmTerm::Ret:
            return; // control de flujo puro: no define registros.
        case AsmTerm::Call:
        case AsmTerm::Indirect:
            cur.clear(); // clobber / destino desconocido (conservador).
            return;
        default: break;
        }
        if (!sem[i].modeled && !flag_write[i]) {
            // No entendemos la instruccion y no consta que escriba flags ->
            // pudo definir cualquier cosa: vacia (conservador).
            cur.clear();
            return;
        }
        for (const std::string &w : sem[i].writes)
            cur.erase(w);
        if (flag_write[i])
            cur.erase(FLAGS); // cmp/add/sub/... definen las flags.
    };

    // Transferencia de un bloque completo.
    auto transfer = [&](uint32_t b, const RegSet &in) -> RegSet {
        RegSet cur = in;
        for (uint32_t i = cfg.blocks[b].first; i <= cfg.blocks[b].last; ++i)
            apply_defs(i, cur);
        return cur;
    };

    // Punto fijo: undef_in(b) = interseccion de undef_out(preds); recomputa
    // undef_out.  Converge (los conjuntos solo decrecen).
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 10000) {
        changed = false;
        for (uint32_t b = 0; b < nb; ++b) {
            if (b != 0 && !cfg.blocks[b].preds.empty()) {
                // Interseccion de los undef_out de los predecesores.
                RegSet meet;
                bool first = true;
                for (uint32_t p : cfg.blocks[b].preds) {
                    if (first) {
                        meet = undef_out[p];
                        first = false;
                    } else {
                        RegSet inter;
                        for (const std::string &r : meet)
                            if (undef_out[p].count(r)) inter.insert(r);
                        meet.swap(inter);
                    }
                }
                if (meet != undef_in[b]) {
                    undef_in[b] = std::move(meet);
                    changed = true;
                }
            }
            RegSet no = transfer(b, undef_in[b]);
            if (no != undef_out[b]) {
                undef_out[b] = std::move(no);
                changed = true;
            }
        }
    }

    // Reporte: recorre cada bloque con su undef_in y detecta lecturas de un
    // registro aun indefinido.  Dedup por (linea, registro).
    std::set<std::pair<uint32_t, std::string>> seen;
    for (uint32_t b = 0; b < nb; ++b) {
        RegSet cur = undef_in[b];
        for (uint32_t i = cfg.blocks[b].first; i <= cfg.blocks[b].last; ++i) {
            // Solo reportamos lecturas de registro de una instruccion MODELADA
            // (si no la entendemos, no afirmamos nada sobre sus operandos).
            if (sem[i].modeled) {
                for (const std::string &r : sem[i].reads) {
                    if (cur.count(r)) {
                        auto key = std::make_pair(cfg.insns[i].line_no, r);
                        if (seen.insert(key).second) {
                            AsmDiag d;
                            d.severity = AsmDiagSeverity::Warning;
                            d.line_no = cfg.insns[i].line_no;
                            d.code = "VXA004";
                            d.args = {r}; // {0} = registro.
                            out.push_back(std::move(d));
                        }
                    }
                }
            }
            // Lectura de flags: se comprueba aunque la instruccion no este
            // modelada (las ramas condicionales no lo estan) -> `jz` antes de
            // cualquier `cmp`/`test` avisa.
            if (flag_read[i] && cur.count(FLAGS)) {
                auto key = std::make_pair(cfg.insns[i].line_no, FLAGS);
                if (seen.insert(key).second) {
                    AsmDiag d;
                    d.severity = AsmDiagSeverity::Warning;
                    d.line_no = cfg.insns[i].line_no;
                    d.code = "VXA005"; // sin args.
                    out.push_back(std::move(d));
                }
            }
            apply_defs(i, cur);
        }
    }

    return out;
}

} // namespace vx
