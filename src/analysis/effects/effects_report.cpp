/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file effects_report.cpp
 * @brief Reporte legible del modelo de efectos (--analyze): efectos +
 *        contratos derivados + lagunas de precision, por proyeccion del
 *        SemanticSummary (misma fuente que consume el compilador).
 */
#include "util/env_flags.h"
#include "analysis/asa/aggregate_facts.h"
#include "analysis/effects/effects_report.h"

#include "ir/ssa_ir.h"
#include "analysis/effects/bounds.h"
#include "analysis/effects/effect_analysis.h"
#include "vx/diag/diag_format.h" // el texto de los motivos vive en el catalogo

#include <cstdlib>
#include <algorithm>
#include "analyze/asm_report.h" // lo que el ASA sabe de cada bloque asm
#include "vx/asm/asm_cfg.h"     // trocear el asm en instrucciones
#include "vx/asm/asm_effects.h" // ISA del objetivo
#include "vx/asm/instr_db.h"    // que rasgo exige cada instruccion

#include <chrono>
#include <map>
#include <set>
#include <utility>
#include <vector>
#include <iostream>
#include <string>
#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace analysis {
namespace effects {

// =========================================================================
//  Color y graficos: solo cuando hay alguien mirando
// =========================================================================

/**
 * @brief ¿Se puede pintar?
 *
 * Solo si la salida es la consola Y nadie ha pedido lo contrario.  Un informe
 * redirigido a un fichero con secuencias de escape dentro es un informe que no
 * se puede procesar, y `NO_COLOR` es la forma estandar de decir "sin adornos".
 */
static bool hay_color(std::ostream &os) {
    if (&os != &std::cout) return false;
    if (util::flag_on(util::FlagId::NoColor)) return false;
#if defined(_WIN32)
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

namespace col {
constexpr const char *kReset = "\033[0m";
constexpr const char *kFuerte = "\033[1m";
constexpr const char *kApagado = "\033[90m";
constexpr const char *kVerde = "\033[32m";
constexpr const char *kCian = "\033[36m";
constexpr const char *kAmbar = "\033[33m";
constexpr const char *kRojo = "\033[31m";
} // namespace col

/// Envuelve @p txt en un color, o lo deja crudo si no se puede pintar.
static std::string tinte(bool color, const char *c, const std::string &txt) {
    if (!color) return txt;
    return std::string(c) + txt + col::kReset;
}

/**
 * @brief El color DICE algo: no es decoracion.
 *
 * Verde lo demostrado, cian lo que se afirma sin cerrar, ambar lo que no se
 * puede elegir, apagado lo que no se ha llegado a observar.  Quien lea en
 * blanco y negro pierde velocidad, no informacion: el texto sigue diciendo lo
 * mismo.
 */
static const char *color_forma(analysis::asa::FormaDeValor f) {
    switch (f) {
    case analysis::asa::FormaDeValor::Compuesto: return col::kVerde;
    case analysis::asa::FormaDeValor::Agregado: return col::kCian;
    case analysis::asa::FormaDeValor::Desconocida: return col::kAmbar;
    default: return col::kApagado;
    }
}

/**
 * @brief Barra de proporcion con bloques Unicode.
 *
 * Los caracteres van como bytes UTF-8 escapados para que el fuente siga siendo
 * ASCII: U+2588 (bloque lleno) y U+2591 (bloque claro).  Una barra dice de un
 * vistazo lo que una fraccion obliga a calcular.
 */
static std::string barra(uint32_t parte, uint32_t total, int ancho = 24) {
    if (total == 0) return std::string();
    const int llenos =
        static_cast<int>((static_cast<double>(parte) / total) * ancho + 0.5);
    std::string out;
    for (int i = 0; i < ancho; ++i)
        out += (i < llenos) ? "\xe2\x96\x88" : "\xe2\x96\x91";
    return out;
}

static const char *loc_kind_name(AbstractLoc::Kind k) {
    switch (k) {
    case AbstractLoc::Kind::None: return "none";
    case AbstractLoc::Kind::Stack: return "stack";
    case AbstractLoc::Kind::Heap: return "heap";
    case AbstractLoc::Kind::Global: return "global";
    case AbstractLoc::Kind::ArgDerived: return "arg";
    case AbstractLoc::Kind::Unknown: return "unknown";
    }
    return "?";
}

static std::string loc_set_str(const LocSet &s) {
    if (s.is_top) return "unknown(*)";
    if (s.locs.empty()) return "-";
    std::string out;
    for (size_t i = 0; i < s.locs.size(); ++i) {
        if (i) out += ",";
        const AbstractLoc &l = s.locs[i];
        out += loc_kind_name(l.kind);
        if (l.id != LOC_GENERIC) out += "#" + std::to_string(l.id);
        // Offset/ancho concretos (modelo preciso): "+off/w".  width 0 = objeto
        // entero -> se omite.
        if (l.width > 0)
            out += "+" + std::to_string(l.off) + "/" + std::to_string(l.width);
    }
    return out;
}

static const char *control_name(ControlKind k) {
    switch (k) {
    case ControlKind::FallThrough: return "fallthrough";
    case ControlKind::Return: return "return";
    case ControlKind::Branch: return "branch";
    case ControlKind::Call: return "call";
    case ControlKind::Throw: return "throw";
    case ControlKind::Suspend: return "suspend";
    case ControlKind::Resume: return "resume";
    case ControlKind::Indirect: return "indirect";
    case ControlKind::NoReturn: return "noreturn";
    }
    return "?";
}

static const char *completeness_name(AnalysisCompleteness c) {
    switch (c) {
    case AnalysisCompleteness::Complete: return "complete";
    case AnalysisCompleteness::Conservative: return "over-approx";
    case AnalysisCompleteness::Unknown: return "unknown";
    }
    return "?";
}

static const char *reason_name(UnknownReason r) {
    switch (r) {
    case UnknownReason::None: return "none";
    case UnknownReason::UnmodeledOp: return "op-sin-modelar";
    case UnknownReason::UnknownMnemonic: return "asm-mnemonico-desconocido";
    case UnknownReason::UnknownIntrinsic: return "intrinsic-desconocido";
    case UnknownReason::UnknownEncoding: return "encoding-desconocido";
    case UnknownReason::UserBarrier: return "barrera-usuario";
    case UnknownReason::DynamicDispatch: return "dispatch-dinamico";
    case UnknownReason::Indirect: return "llamada-indirecta";
    case UnknownReason::UnknownFFI: return "ffi-nativo";
    case UnknownReason::ExternalCallee: return "callee-externo";
    case UnknownReason::UnknownRuntime: return "runtime-opaco";
    }
    return "?";
}

static void print_effects(std::ostream &os, const SemanticEffects &e) {
    os << "    reads      : " << loc_set_str(e.mem.reads) << "\n";
    os << "    writes     : " << loc_set_str(e.mem.writes) << "\n";
    os << "    control    : " << control_name(e.control.kind) << "\n";
    std::string may;
    auto add = [&](bool b, const char *n) {
        if (b) {
            if (!may.empty()) may += " ";
            may += n;
        }
    };
    add(e.may_trap, "trap");
    add(e.may_throw, "throw");
    add(e.may_allocate, "allocate");
    add(e.may_block, "block");
    add(e.may_io, "io");
    os << "    may        : " << (may.empty() ? "-" : may) << "\n";
    std::string det;
    auto addd = [&](DeterminismTag t, const char *n) {
        if (e.determinism.has(t)) {
            if (!det.empty()) det += " ";
            det += n;
        }
    };
    addd(DeterminismTag::ReadsClock, "clock");
    addd(DeterminismTag::ReadsRandom, "random");
    addd(DeterminismTag::ReadsPID, "pid");
    addd(DeterminismTag::ReadsEnvironment, "env");
    addd(DeterminismTag::ExternalObservable, "external");
    os << "    nondeterm  : " << (det.empty() ? "- (determinista)" : det)
       << "\n";
    std::string tags;
    auto addt = [&](CapabilityTag t, const char *n) {
        if (e.tags.has(t)) {
            if (!tags.empty()) tags += " ";
            tags += n;
        }
    };
    addt(CapabilityTag::MachineState, "machine");
    addt(CapabilityTag::InterruptState, "irq");
    addt(CapabilityTag::PortIO, "portio");
    addt(CapabilityTag::MSR, "msr");
    addt(CapabilityTag::CPUID, "cpuid");
    addt(CapabilityTag::Privileged, "priv");
    addt(CapabilityTag::UserBarrier, "barrier");
    if (!tags.empty()) os << "    tags       : " << tags << "\n";
}

/**
 * @brief Las REGIONES de la funcion con su extension.
 *
 * Hasta ahora el analisis decia DONDE toca una operacion (`heap#3+0/8`) pero no
 * hasta donde llega el objeto, y sin eso "fuera de region" no es decidible: se
 * puede afirmar la direccion, no si se sale.  El dato esta en el sitio de
 * asignacion -- `malloc(64)`, `u8[16] a` -- y aqui se enseña, que es el paso
 * previo a poder señalar un desbordamiento.
 *
 * Se distingue tamano CONSTANTE de SIMBOLICO: simbolico no es desconocido --
 * se sabe que valor lo manda --, y es lo que un rango podra acotar despues.
 */
static void print_regiones(std::ostream &os, EffectAnalysis &ea,
                           const ir::IrFunction &fn) {
    const analysis::PointsTo &pt = ea.points_to_publico(fn);
    std::string out;
    for (uint32_t v = 0; v < pt.extent.size(); ++v) {
        const analysis::RegionExtent &ex = pt.extent[v];
        if (!ex.conocida()) continue;
        const PointsToEntry &e = pt.at(v);
        if (e.kind == AbstractLoc::Kind::Unknown) continue;
        LocSet uno;
        uno.add(AbstractLoc{e.kind, v, 0, 0});
        out += "    " + loc_set_str(uno) + ": ";
        if (ex.constante())
            out += std::to_string(ex.bytes) + " bytes";
        else
            out += "tamano en %" + std::to_string(ex.sym) + " (simbolico)";
        out += "\n";
    }
    if (!out.empty()) os << "  Regiones:\n" << out;
}

/**
 * @brief Accesos que se salen de su region, DEMOSTRADOS.
 *
 * NO reimplementa el veredicto: llama al MISMO comprobador que usa el
 * compilador (`analysis::effects::check_region_bounds`).  Lo que cambia entre
 * los dos no es el criterio, es que hacer con el: al construir corta, al
 * analizar se enseña con la prueba delante.
 */
static void print_fuera_de_region(std::ostream &os, const ir::IrModule &mod,
                                  EffectAnalysis &ea) {
    const std::vector<BoundsViolation> vs = check_region_bounds(mod, &ea);
    if (vs.empty()) return;
    os << "\n=== Accesos fuera de region (demostrados) ===\n";
    for (const BoundsViolation &v : vs) {
        os << "  " << v.function << " (linea " << v.line
           << "): " << (v.write ? "escritura" : "lectura") << " de " << v.width
           << " bytes fuera de " << v.region << "\n";
        os << "    prueba: objeto = " << v.objeto << " bytes, hueco = [0, "
           << v.limite << ") ; acceso = [" << v.off << ", " << (v.off + v.width)
           << ")\n";
    }
}

/**
 * @brief Los PRESTAMOS de la funcion, tal como cruzan al IR.
 *
 * El borrow checker demuestra cosas -- sobre todo que un prestamo mutable es
 * EXCLUSIVO -- y hasta ahora eso moria dentro del type checker, sin llegar al
 * analisis.  Verlos aqui es lo que permite comprobar que el hecho que cruza
 * dice lo mismo que el checker, antes de que nadie razone sobre el.
 *
 * Se dice la NATURALEZA de lo prestado porque no se mezclan: prestar un
 * `unique` no es prestar un local, y un puntero crudo no esta sujeto a estas
 * reglas en absoluto.
 */
static void print_prestamos(std::ostream &os, const ir::IrFunction &fn) {
    if (fn.borrow_facts.empty()) return;
    auto nat = [](ir::IrFunction::BorrowOwnerKind k) {
        switch (k) {
        case ir::IrFunction::BorrowOwnerKind::Unique: return "unique";
        case ir::IrFunction::BorrowOwnerKind::Shared: return "shared";
        case ir::IrFunction::BorrowOwnerKind::Reborrow: return "represtamo";
        default: return "local";
        }
    };
    os << "  Prestamos:\n";
    for (const ir::IrFunction::BorrowFact &b : fn.borrow_facts) {
        os << "    " << (b.mutable_ ? "exclusivo" : "compartido") << " de "
           << (b.owner_name.empty() ? "?" : b.owner_name) << " ("
           << nat(b.owner_kind) << ") en linea " << b.line << "\n";
    }
}

/**
 * @brief Los CONFLICTOS de memoria de una funcion, para que se puedan resolver.
 *
 * Un conflicto es lo que impide tratar dos accesos por separado: tocan memoria
 * que puede ser la misma y al menos uno escribe.  Es lo que bloquea mover una
 * lectura fuera de un bucle, eliminar una escritura o reordenar dos accesos, y
 * hasta ahora se quedaba dentro del compilador: el informe decia el efecto de
 * cada funcion pero no CONTRA QUE choca.  Sabiendolo, se puede cambiar el
 * codigo -- separar los objetos, no aliasar, acotar un puntero -- y recuperar
 * la optimizacion; sin saberlo solo queda adivinar.
 *
 * Se anclan en la LIBERACION porque es donde ademas hay un fallo que ensenar:
 * un acceso a memoria ya liberada.  Solo se afirma dentro del mismo bloque y
 * en orden -- ahi el "despues" es cierto, sin depender de por donde vaya el
 * flujo --, y solo con localizaciones precisas: sobre "cualquier sitio" todo
 * choca con todo y el aviso no diria nada.
 */
static void print_conflictos(std::ostream &os, EffectAnalysis &ea,
                             const ir::IrFunction &fn) {
    struct Acc {
        uint32_t line = 0;
        bool escribe = false;
        AbstractLoc loc;
    };
    std::string out;
    unsigned n = 0;
    for (const ir::IrBlock &b : fn.blocks) {
        // Accesos del bloque, en orden.  Uno por localizacion tocada.
        std::vector<Acc> accs;
        std::vector<size_t> libera; // indices de accs que son una liberacion
        for (const ir::IrInstr &in : b.instrs) {
            const EffectAnalysisResult r = ea.local(fn, in);
            const bool es_free = (in.op == ir::IrOp::RAW_FREE ||
                                  in.op == ir::IrOp::SMARTPTR_FREE);
            auto anota = [&](const LocSet &ls, bool escribe) {
                if (ls.is_top) return;
                for (const AbstractLoc &l : ls.locs) {
                    if (l.kind == AbstractLoc::Kind::Unknown ||
                        l.kind == AbstractLoc::Kind::None)
                        continue;
                    if (es_free && escribe) libera.push_back(accs.size());
                    accs.push_back({in.source_line, escribe, l});
                }
            };
            anota(r.effects.mem.reads, false);
            anota(r.effects.mem.writes, true);
        }
        for (size_t li : libera) {
            for (size_t j = li + 1; j < accs.size() && n < 8; ++j) {
                if (!may_alias(accs[li].loc, accs[j].loc)) continue;
                LocSet uno;
                uno.add(accs[li].loc);
                out += "    " + loc_set_str(uno) + ": liberada en linea " +
                       std::to_string(accs[li].line) + ", " +
                       (accs[j].escribe ? "escrita" : "leida") +
                       " despues en " + std::to_string(accs[j].line) + "\n";
                ++n;
            }
        }
    }
    if (!out.empty())
        os << "  Conflictos de memoria (acceso a memoria ya liberada):\n"
           << out;
}

/**
 * @brief FORMA de los valores con componentes, con su alcance y sus limites.
 *
 * Se muestra lo que se demostro Y donde vale: un valor cuya forma global no se
 * puede afirmar puede tener dentro ambitos cerrados donde SI esta demostrada, y
 * ensenar solo el veredicto global tira ese conocimiento.
 *
 * Y lo que impide demostrar mas se dice tambien, con su sitio: es lo unico que
 * convierte un "no se" en algo accionable -- dice QUE habria que poder ver.
 */
static void print_formas_de(std::ostream &os,
                            const analysis::asa::ObservacionModulo &modelo,
                            const char *estado) {
    os << "  --- " << estado << " ---\n";
    /* Se ordena por lo que FALTA, no por orden de aparicion.  Un informe que
     * empieza por lo demostrado se lee y se cierra; uno que empieza por lo que
     * no se sabe dirige la atencion a donde hay algo que hacer.  Dentro de cada
     * grupo se conserva el orden del modulo, que es estable. */
    std::vector<
        std::pair<analysis::asa::IdentidadValor, analysis::asa::AggregateFacts>>
        todos = modelo.valores;
    auto urgencia = [](const analysis::asa::AggregateFacts &a) {
        // 0 = no se puede elegir, 1 = no se llego a observar, 2 = se sale o no
        // se pudo seguir, 3 = demostrado.  Menor va antes.
        const analysis::asa::FormaDeValor f = a.forma();
        if (f == analysis::asa::FormaDeValor::Desconocida) return 0;
        if (f == analysis::asa::FormaDeValor::SinEvidencia) return 1;
        if (!a.fronteras.empty() || !a.limitaciones.empty()) return 2;
        return 3;
    };
    std::stable_sort(todos.begin(), todos.end(),
                     [&](const auto &x, const auto &y) {
                         return urgencia(x.second) < urgencia(y.second);
                     });
    bool alguno = false;
    {
        std::string fn_actual;
        for (const auto &par : todos) {
            alguno = true;
            if (par.first.funcion != fn_actual) {
                fn_actual = par.first.funcion;
                os << "  " << fn_actual << "\n";
            }
            const analysis::asa::AggregateFacts &a = par.second;
            {
                /* De donde sale el valor: una linea del cuerpo o la firma.  Y
                 * su tamano solo si se sabe -- de un parametro lo sabe quien
                 * llama. */
                if (a.declaracion.linea == 0 && a.declaracion.indice > 0)
                    os << "    parametro " << a.declaracion.indice << "  ";
                else
                    os << "    linea " << a.declaracion.linea << ":"
                       << a.declaracion.indice << "  ";
                if (a.bytes >= 0)
                    os << a.bytes << " bytes, ";
                else
                    os << "tamano no conocido aqui, ";
                const bool color = hay_color(os);
                const analysis::asa::FormaDeValor f = a.forma();
                os << a.offsets_tocados() << " desplazamientos  -> "
                   << tinte(color, color_forma(f),
                            analysis::asa::nombre_forma(f))
                   << " / "
                   << tinte(color,
                            a.seal.certainty == analysis::asa::Certainty::Proven
                                ? col::kVerde
                                : (a.seal.certainty ==
                                           analysis::asa::Certainty::Inferred
                                       ? col::kCian
                                       : col::kApagado),
                            analysis::asa::certainty_name(a.seal.certainty))
                   << "\n";
                for (analysis::asa::MotivoForma mo : a.motivos_forma())
                    os << "        porque: " << analysis::asa::nombre_motivo(mo)
                       << "\n";
                /* Las verdades LOCALES: un ambito cerrado demuestra lo suyo
                 * aunque el de fuera no.  Sin esto, un "sin evidencia" global
                 * esconderia todo lo que si se sabe por dentro. */
                for (const analysis::asa::Universo &u : a.universos) {
                    if (!u.cerrado || u.id == 0) continue;
                    const analysis::asa::FormaDeValor f = a.forma_en(u.id);
                    if (f == analysis::asa::FormaDeValor::SinEvidencia)
                        continue;
                    os << "        en " << u.ambito << ": "
                       << analysis::asa::nombre_forma(f)
                       << " (demostrado ahi)\n";
                }
                for (const analysis::asa::Frontera &fr : a.fronteras)
                    os << "        sale por "
                       << analysis::asa::nombre_frontera(fr.codigo) << " en "
                       << fr.sitio.funcion << ":" << fr.sitio.linea << "\n";
                for (const analysis::asa::Limitacion &l : a.limitaciones) {
                    os << "        no pude seguir: "
                       << analysis::asa::nombre_limitacion(l.codigo) << " en "
                       << l.sitio.funcion << ":" << l.sitio.linea
                       << (l.destino.empty() ? "" : " -> " + l.destino);
                    /* Y de que CLASE es, que es lo que dice si hay algo que
                     * hacer: "depende de la ejecucion" admite una guarda y
                     * "forma no reconocida" se arregla ampliando el analisis.
                     * Sin esto, todas las limitaciones se leian igual. */
                    if (l.reason != analysis::asa::UnknownReason::NotAsked)
                        os << "  ["
                           << analysis::asa::unknown_reason_name(l.reason)
                           << (l.reason_code != nullptr &&
                                       l.reason_code[0] != '\0'
                                   ? std::string(": ") + l.reason_code
                                   : std::string())
                           << "]";
                    os << "\n";
                }
            }
        }
    }
    if (!alguno) os << "    ninguno en este estado.\n";
}

/**
 * @brief Las DOS realidades del programa, no una.
 *
 * Antes y despues de optimizar son dos verdades del mismo programa, y ninguna
 * es la correcta en abstracto: la primera describe lo que se escribio, la
 * segunda lo que de verdad queda.  Ensenar solo la segunda hace decir "no hay
 * ningun valor con componentes" de un programa que tiene seis.
 */
/**
 * @brief Mapa de COBERTURA: hasta donde ha llegado la observacion.
 *
 * No es una medida de precision.  Que una region sea opaca -- una nativa, un
 * destino que no se resuelve -- no dice que el analisis sea impreciso: dice que
 * hay un sitio cuyo comportamiento no se ha podido demostrar DESDE AQUI.  Son
 * cosas distintas y confundirlas hace leer una limitacion del alcance como un
 * defecto de calidad.
 *
 * Y lo que se cuenta no es "cuanto se sabe" sino "cuanto se ha podido mirar":
 * ambitos cerrados, ambitos que se saben nombrar pero no se han abierto, y
 * fronteras por las que el conocimiento se sale.  Es el mapa que dice DONDE
 * habria que mirar para saber mas.
 */
static void
print_cobertura_formas(std::ostream &os,
                       const analysis::asa::ObservacionModulo &modelo,
                       const char *estado) {
    uint32_t observados = 0, fronteras = 0, limitaciones = 0;
    uint32_t valores = 0, con_forma = 0, demostrados = 0;
    /* Los ambitos que se saben nombrar y no se han abierto son una LISTA DE
     * TRABAJO: dicen exactamente donde mirar para saber mas.  Un contador no
     * acciona nada; el nombre si. */
    std::map<std::string, uint32_t> sin_abrir;
    {
        for (const auto &par : modelo.valores) {
            const analysis::asa::AggregateFacts &a = par.second;
            ++valores;
            if (a.forma() != analysis::asa::FormaDeValor::SinEvidencia &&
                a.forma() != analysis::asa::FormaDeValor::Desconocida)
                ++con_forma;
            if (a.seal.certainty == analysis::asa::Certainty::Proven)
                ++demostrados;
            fronteras += static_cast<uint32_t>(a.fronteras.size());
            limitaciones += static_cast<uint32_t>(a.limitaciones.size());
            for (const analysis::asa::Universo &u : a.universos) {
                if (u.observacion ==
                    analysis::asa::EstadoObservacion::Observado)
                    ++observados;
                else if (u.identidad ==
                         analysis::asa::IdentidadUniverso::Conocido)
                    ++sin_abrir[u.ambito];
            }
        }
    }
    if (valores == 0) return;
    os << "  forma de los valores (" << estado << "):\n";
    const bool color = hay_color(os);
    auto linea = [&](const char *etiqueta, uint32_t n, uint32_t total,
                     const char *c) {
        os << "    " << etiqueta << " " << tinte(color, c, std::to_string(n));
        if (total > 0 && n <= total)
            os << "  " << tinte(color, c, barra(n, total)) << " "
               << (total ? (n * 100 / total) : 0) << "%";
        os << "\n";
    };
    linea("valores observados             :", valores, 0, col::kFuerte);
    linea("  con forma afirmable          :", con_forma, valores, col::kVerde);
    linea("  demostrados (ambito cerrado) :", demostrados, valores,
          col::kVerde);
    linea("ambitos abiertos y mirados     :", observados, 0, col::kCian);
    linea("fronteras por las que se sale  :", fronteras, 0, col::kAmbar);
    linea("sitios que no se pudieron seguir:", limitaciones, 0, col::kAmbar);
    if (!sin_abrir.empty()) {
        uint32_t n = 0;
        for (const auto &kv : sin_abrir)
            n += kv.second;
        linea("ambitos que se saben y no se han mirado:", n, 0, col::kAmbar);
        for (const auto &kv : sin_abrir)
            os << "      " << tinte(color, col::kApagado, kv.first) << " x"
               << kv.second << "\n";
    }
}

/**
 * @brief Vista de lo que cambio entre los dos estados.
 *
 * El emparejamiento NO se hace aqui: es un hecho de ASA (`comparar_estados`), y
 * esta vista solo lo presenta.  Si viviera en el informe, quien quisiera el
 * mismo dato sin pasar por el texto -- una herramienta, un modelo -- tendria
 * que reimplementarlo, y dos implementaciones del mismo hecho acaban
 * discrepando.
 */
static void
print_transiciones(std::ostream &os,
                   const analysis::asa::ObservacionModulo &antes,
                   const analysis::asa::ObservacionModulo &despues) {
    const auto ts = analysis::asa::comparar_estados(antes, despues);
    if (ts.empty()) return;
    const bool color = hay_color(os);
    uint32_t n_ido = 0, n_igual = 0, n_cambia = 0, n_nuevo = 0,
             n_sin_emparejar = 0;
    std::string detalle;
    for (const analysis::asa::TransicionValor &t : ts) {
        const std::string donde =
            t.valor.funcion +
            (t.valor.linea > 0
                 ? " linea " + std::to_string(t.valor.linea)
                 : " parametro " + std::to_string(t.valor.indice)) +
            (t.valor.orden > 0 ? " #" + std::to_string(t.valor.orden + 1) : "");
        switch (t.tipo) {
        case analysis::asa::TipoTransicion::Sobrevive: ++n_igual; break;
        case analysis::asa::TipoTransicion::Desaparece:
            ++n_ido;
            detalle += "    " + tinte(color, col::kRojo, donde) + ": " +
                       analysis::asa::nombre_forma(t.antes) +
                       " -> ya no existe (se lo llevo una transformacion)\n";
            break;
        case analysis::asa::TipoTransicion::CambiaForma:
            ++n_cambia;
            detalle +=
                "    " + tinte(color, col::kFuerte, donde) + ": " +
                tinte(color, color_forma(t.antes),
                      analysis::asa::nombre_forma(t.antes)) +
                " -> " +
                tinte(color, color_forma(t.despues),
                      analysis::asa::nombre_forma(t.despues)) +
                tinte(color, col::kAmbar, "   (cambio semantico: revisar)") +
                "\n";
            break;
        case analysis::asa::TipoTransicion::NoEmparejable:
            ++n_sin_emparejar;
            detalle += "    " + tinte(color, col::kApagado, donde) +
                       ": varios valores comparten sitio y cambio su numero; "
                       "no se puede decir cual es cual\n";
            break;
        case analysis::asa::TipoTransicion::Aparece:
            ++n_nuevo;
            detalle += "    " + tinte(color, col::kCian, donde) +
                       ": aparece al optimizar (" +
                       analysis::asa::nombre_forma(t.despues) + ")\n";
            break;
        }
    }
    os << "  --- que cambio entre los dos estados ---\n";
    os << "    sobreviven igual: "
       << tinte(color, col::kVerde, std::to_string(n_igual))
       << "   desaparecen: " << tinte(color, col::kRojo, std::to_string(n_ido))
       << "   cambian de forma: "
       << tinte(color, n_cambia ? col::kAmbar : col::kApagado,
                std::to_string(n_cambia))
       << "\n";
    if (n_sin_emparejar > 0)
        os << "    sin poder emparejar: "
           << tinte(color, col::kApagado, std::to_string(n_sin_emparejar))
           << "  (varios valores en el mismo sitio del fuente)\n";
    os << detalle;
}

static void print_formas(std::ostream &os,
                         const analysis::asa::ObservacionModulo &final_m,
                         const analysis::asa::ObservacionModulo *previo_m) {
    os << "=== Forma de los valores con componentes ===\n";
    if (previo_m != nullptr)
        print_formas_de(os, *previo_m, "tal como se escribio");
    print_formas_de(os, final_m, "en el codigo final");
    // El orden importa: primero el estado de ANTES.  Invertirlo daba la
    // transicion del reves y el informe decia lo contrario de lo que pasa.
    if (previo_m != nullptr) print_transiciones(os, *previo_m, final_m);
    os << "\n";
}

void print_effects_report(std::ostream &os, const ir::IrModule &mod,
                          Backend backend, const ir::IrModule *mod_previo) {
    /* Reparto del coste del informe.  Cada seccion mira el programa entero, asi
     * que "el analisis tarda" solo se puede atacar sabiendo cual de ellas. */
    const bool medir = util::flag_on(util::FlagId::Times);
    using RelojInf = std::chrono::steady_clock;
    auto marca = RelojInf::now();
    long us_resumen = 0, us_observar = 0, us_funciones = 0, us_formas = 0,
         us_limites = 0, us_resto = 0;
    auto cerrar = [&](long &destino) {
        const auto ahora = RelojInf::now();
        destino += static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(ahora - marca)
                .count());
        marca = ahora;
    };

    EffectAnalysis ea;
    ea.set_backend(backend);
    const ModuleSummary &ms = ea.module_summary(mod);
    cerrar(us_resumen);
    /* El conocimiento se observa UNA vez por estado; las vistas de abajo son
     * proyecciones sobre el.  Antes cada una lo recalculaba, y nada garantizaba
     * que dos vistas hablaran del mismo grafo. */
    const analysis::asa::ObservacionModulo modelo_final =
        analysis::asa::observar_modulo(mod);
    const analysis::asa::ObservacionModulo modelo_previo =
        mod_previo != nullptr ? analysis::asa::observar_modulo(*mod_previo)
                              : analysis::asa::ObservacionModulo{};
    cerrar(us_observar);

    /* Se dice para QUIEN.  Un efecto no es una propiedad del IR a secas: las
     * ops que dependen del runtime son una instruccion en la maquina virtual y
     * una llamada a libvesta_rt en nativo, y hay quien directamente no existe
     * fuera de la VM.  Un informe que no diga desde donde mira invita a leerlo
     * como si valiera para los tres. */
    /* Un resumen antes de cuatrocientas lineas.  No sustituye a nada de lo que
     * viene despues: da el contexto para leerlo, y dice de entrada si hay algo
     * que mirar o no. */
    {
        const bool color = hay_color(os);
        const analysis::asa::ObservacionModulo &fuente =
            mod_previo != nullptr ? modelo_previo : modelo_final;
        /* Tres cuentas distintas, porque responden a preguntas distintas:
         * cuantos valores se MIRARON, de cuantos se demostro que tienen
         * componentes, y cuantos quedaron con algo abierto.  Dar solo la
         * primera hace creer que todos dicen algo; dar solo la segunda esconde
         * lo que el analisis no alcanzo. */
        uint32_t valores = 0, con_forma = 0, demostrados = 0, sin_cerrar = 0;
        {
            for (const auto &par : fuente.valores) {
                const analysis::asa::AggregateFacts &a = par.second;
                ++valores;
                const analysis::asa::FormaDeValor f = a.forma();
                if (f == analysis::asa::FormaDeValor::Agregado ||
                    f == analysis::asa::FormaDeValor::Compuesto)
                    ++con_forma;
                if (a.seal.certainty == analysis::asa::Certainty::Proven)
                    ++demostrados;
                if (!a.fronteras.empty() || !a.limitaciones.empty())
                    ++sin_cerrar;
            }
        }
        os << tinte(color, col::kFuerte, "Resumen") << ": "
           << mod.functions.size() << " funciones";
        if (valores > 0)
            os << ", " << valores << " valores observados (" << con_forma
               << " con componentes, "
               << tinte(color, col::kVerde, std::to_string(demostrados))
               << " con forma demostrada, "
               << tinte(color, sin_cerrar ? col::kAmbar : col::kApagado,
                        std::to_string(sin_cerrar))
               << " sin cerrar)";
        os << "\n";
        os << "Se analiza para el backend " << backend_name(backend)
           << "; las secciones que hablan del programa lo hacen en sus DOS "
              "estados (fuente y codigo final).\n\n";
    }

    os << "=== Efectos y contratos (modelo unico) -- backend: "
       << backend_name(backend) << " ===\n\n";
    // Orden estable: el de mod.functions.
    for (const ir::IrFunction &fn : mod.functions) {
        auto it = ms.fns.find(fn.name);
        if (it == ms.fns.end()) continue;
        const FunctionSummary &s = it->second;

        os << fn.name << "\n";
        /* Los que SE CUMPLEN, y detras los que NO con su motivo.  Saber que un
         * contrato falla sin saber por que obliga a ir a leer los efectos y
         * deducirlo; el predicado ya lo sabe, asi que lo dice.  El texto sale
         * del catalogo multi-idioma: aqui no se redacta nada. */
        std::string contracts;
        std::string fallidos;
        for (const EvaluatedContract &c : derive_contracts(s)) {
            if (c.holds) {
                if (!contracts.empty()) contracts += " ";
                contracts += c.name;
                continue;
            }
            std::string motivos;
            for (ContractReason r : c.motivos) {
                if (!motivos.empty()) motivos += ", ";
                motivos += vx::diag::format(contract_reason_code(r), {});
            }
            if (motivos.empty()) continue;
            fallidos += "                ";
            fallidos += c.name;
            fallidos += ": ";
            fallidos += motivos;
            fallidos += "\n";
        }
        os << "  Contratos : " << (contracts.empty() ? "-" : contracts) << "\n";
        if (!fallidos.empty()) os << "    no cumple:\n" << fallidos;
        os << "  Analisis  : " << completeness_name(s.completeness) << "\n";
        /* QUE juegos de instrucciones usa.
         *
         * Una funcion con un `asm` puede exigir del procesador cosas que no se
         * ven en su firma: AVX-512, AES, ERMS.  Eso decide DONDE puede correr,
         * y hasta ahora solo se sabia al reventar -- el fallo en ejecucion dice
         * "exige AVX512F" cuando ya es tarde.  Aqui se dice antes, y sale de la
         * misma base de instrucciones, asi que vale para cualquier ISA sin
         * escribir aqui ni un nombre de instruccion. */
        {
            std::set<std::string> rasgos;
            const vx::instr_db::Isa isa_db = vx::isa_actual();
            for (const ir::IrBlock &b : fn.blocks) {
                for (const ir::IrInstr &in : b.instrs) {
                    std::string cuerpo;
                    if (in.op == ir::IrOp::INLINE_ASM) {
                        cuerpo = in.func_name;
                    } else if (in.op == ir::IrOp::ASM_MICRO &&
                               in.imm < fn.asm_micros.size()) {
                        cuerpo = fn.asm_micros[in.imm].tmpl;
                    } else {
                        continue;
                    }
                    for (const vx::AsmInsn &ai :
                         vx::build_asm_cfg(isa_db, cuerpo).insns) {
                        if (ai.sintetica) continue;
                        const int32_t fid =
                            vx::instr_db::match_asm_line(isa_db, ai.text);
                        if (fid < 0) continue;
                        const std::string r = vx::instr_db::nombre_de_rasgo(
                            vx::instr_db::isa_set_of(isa_db, fid));
                        if (!r.empty()) rasgos.insert(r);
                    }
                }
            }
            if (!rasgos.empty()) {
                os << "  Rasgos    : ";
                bool primero = true;
                for (const std::string &r : rasgos) {
                    if (!primero) os << ", ";
                    os << r;
                    primero = false;
                }
                os << "   (los exige el procesador donde corra)\n";
            }
        }
        os << "  Efecto local:\n";
        print_effects(os, s.semantic.local);
        os << "  Efecto transitivo (cierre):\n";
        print_effects(os, s.semantic.closure);
        os << "  Estructura: bloques=" << s.structural.block_count
           << " bucles=" << s.structural.loop_count
           << (s.structural.recursive ? " recursiva" : "") << "\n";
        print_regiones(os, ea, fn);
        print_prestamos(os, fn);
        print_conflictos(os, ea, fn);
        os << "\n";
    }
    cerrar(us_funciones);

    // La FORMA de los valores con componentes: saco de partes o unidad.  Va en
    // el informe y no detras de una variable de entorno porque es conocimiento
    // sobre el programa del usuario, no depuracion del compilador.
    print_formas(os, modelo_final,
                 mod_previo != nullptr ? &modelo_previo : nullptr);

    /* Y lo que el ASA sabe de cada bloque de ensamblador.  Va en el informe
     * porque es conocimiento sobre el programa del usuario -- que exige del
     * procesador, cuanto de el se entiende --, no depuracion del compilador. */
    analyze::print_asm_report(os, analyze::analizar_bloques_asm(mod));
    cerrar(us_formas);

    // Reporte de LAGUNAS: hace visible que falta por modelar (cobertura) y
    // donde la opacidad es fundamental (oportunidades de opt del lado del
    // usuario).
    print_fuera_de_region(os, mod, ea);
    cerrar(us_limites);

    auto publicar = [&]() {
        cerrar(us_resto);
        if (!medir) return;
        std::cerr << "[informe] " << mod.functions.size()
                  << " funciones | resumen " << us_resumen << " us | observar "
                  << us_observar << " us | por-funcion " << us_funciones
                  << " us | formas " << us_formas << " us | limites "
                  << us_limites << " us | resto " << us_resto << " us\n";
    };

    const EffectGaps &g = ea.gaps();
    os << "=== Cobertura del conocimiento ===\n";
    /* La cobertura tambien es de los DOS estados: contar solo el codigo
     * final decia "2 valores" de un programa cuyo fuente tiene ocho. */
    if (mod_previo != nullptr)
        print_cobertura_formas(os, modelo_previo, "tal como se escribio");
    print_cobertura_formas(os, modelo_final, "en el codigo final");
    if (g.empty()) {
        os << "  efectos: todos se infirieron sin subir al maximo.\n";
        publicar();
        return;
    }
    os << "  sitios que subieron al efecto maximo (top): " << g.total_top
       << "\n";
    os << "  por motivo:\n";
    for (const auto &kv : g.by_reason)
        os << "    " << reason_name(kv.first) << " x" << kv.second
           << (reason_is_gap(kv.first) ? "   (LAGUNA del motor -- modelable)"
                                       : "   (opacidad fundamental)")
           << "\n";
    if (!g.unmodeled_ops.empty()) {
        os << "  IrOps sin modelar (mejorar cobertura del motor):\n";
        for (const auto &kv : g.unmodeled_ops)
            os << "    " << ir::ir_op_name(static_cast<ir::IrOp>(kv.first))
               << " x" << kv.second << "\n";
    }
    /* Y CUALES son las instrucciones de asm que no se saben explicar.  Sin el
     * nombre no se puede cerrar la laguna, y cerrarla -- anadir la instruccion
     * a la tabla -- es la forma prevista de que el analizador crezca. */
    if (!g.nativas_desconocidas.empty()) {
        os << "  Funciones nativas sin efectos declarados (declararlas cierra "
              "la laguna):\n";
        for (const auto &kv : g.nativas_desconocidas)
            os << "    " << kv.first << " x" << kv.second << "\n";
    }
    if (!g.mnemonicos_desconocidos.empty()) {
        os << "  Instrucciones de asm sin tabular (anadirlas cierra la "
              "laguna):\n";
        for (const auto &kv : g.mnemonicos_desconocidos)
            os << "    " << kv.first << " x" << kv.second << "\n";
    }
    publicar();
}

// ---- Proyeccion JSON (misma fuente que el reporte legible) ----

static std::string json_escape(const std::string &s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\') o.push_back('\\');
        o.push_back(c);
    }
    return o;
}

// Emite un array JSON de banderas may_* activas.
static void may_json(std::ostream &os, const SemanticEffects &e) {
    const char *sep = "";
    os << "[";
    auto add = [&](bool b, const char *n) {
        if (b) {
            os << sep << "\"" << n << "\"";
            sep = ",";
        }
    };
    add(e.may_trap, "trap");
    add(e.may_throw, "throw");
    add(e.may_allocate, "allocate");
    add(e.may_block, "block");
    add(e.may_io, "io");
    os << "]";
}

static void nondeterm_json(std::ostream &os, const SemanticEffects &e) {
    const char *sep = "";
    os << "[";
    auto add = [&](DeterminismTag t, const char *n) {
        if (e.determinism.has(t)) {
            os << sep << "\"" << n << "\"";
            sep = ",";
        }
    };
    add(DeterminismTag::ReadsClock, "clock");
    add(DeterminismTag::ReadsRandom, "random");
    add(DeterminismTag::ReadsPID, "pid");
    add(DeterminismTag::ReadsEnvironment, "env");
    add(DeterminismTag::ExternalObservable, "external");
    os << "]";
}

static void tags_json(std::ostream &os, const SemanticEffects &e) {
    const char *sep = "";
    os << "[";
    auto add = [&](CapabilityTag t, const char *n) {
        if (e.tags.has(t)) {
            os << sep << "\"" << n << "\"";
            sep = ",";
        }
    };
    add(CapabilityTag::MachineState, "machine");
    add(CapabilityTag::InterruptState, "irq");
    add(CapabilityTag::PortIO, "portio");
    add(CapabilityTag::MSR, "msr");
    add(CapabilityTag::CPUID, "cpuid");
    add(CapabilityTag::Privileged, "priv");
    add(CapabilityTag::UserBarrier, "barrier");
    os << "]";
}

// Serializa un SemanticEffects como objeto JSON (mismos campos que
// print_effects).
static void effects_obj_json(std::ostream &os, const SemanticEffects &e) {
    os << "{\"reads\":\"" << json_escape(loc_set_str(e.mem.reads)) << "\""
       << ",\"writes\":\"" << json_escape(loc_set_str(e.mem.writes)) << "\""
       << ",\"control\":\"" << control_name(e.control.kind) << "\"";
    os << ",\"may\":";
    may_json(os, e);
    os << ",\"nondeterm\":";
    nondeterm_json(os, e);
    os << ",\"tags\":";
    tags_json(os, e);
    os << "}";
}

void effects_json(std::ostream &os, const ir::IrModule &mod, Backend backend) {
    EffectAnalysis ea;
    ea.set_backend(backend);
    const ModuleSummary &ms = ea.module_summary(mod);

    os << "{\"functions\":[";
    bool first = true;
    for (const ir::IrFunction &fn : mod.functions) {
        auto it = ms.fns.find(fn.name);
        if (it == ms.fns.end()) continue;
        const FunctionSummary &s = it->second;
        if (!first) os << ",";
        first = false;

        os << "{\"function\":\"" << json_escape(fn.name) << "\""
           << ",\"completeness\":\"" << completeness_name(s.completeness)
           << "\"";
        // Contratos derivados que se cumplen.
        os << ",\"contracts\":[";
        const char *csep = "";
        for (const EvaluatedContract &c : derive_contracts(s))
            if (c.holds) {
                os << csep << "\"" << json_escape(c.name) << "\"";
                csep = ",";
            }
        os << "]";
        os << ",\"local\":";
        effects_obj_json(os, s.semantic.local);
        os << ",\"closure\":";
        effects_obj_json(os, s.semantic.closure);
        os << ",\"structure\":{\"blocks\":" << s.structural.block_count
           << ",\"loops\":" << s.structural.loop_count
           << ",\"recursive\":" << (s.structural.recursive ? "true" : "false")
           << "}}";
    }
    os << "]";

    // Lagunas de precision (cobertura + opacidad fundamental) para los
    // diagramas.
    const EffectGaps &g = ea.gaps();
    os << ",\"gaps\":{\"total_top\":" << g.total_top << ",\"by_reason\":[";
    bool rfirst = true;
    for (const auto &kv : g.by_reason) {
        if (!rfirst) os << ",";
        rfirst = false;
        os << "{\"reason\":\"" << reason_name(kv.first) << "\""
           << ",\"kind\":\""
           << (reason_is_gap(kv.first) ? "gap" : "fundamental") << "\""
           << ",\"count\":" << kv.second << "}";
    }
    os << "],\"unmodeled_ops\":[";
    bool ofirst = true;
    for (const auto &kv : g.unmodeled_ops) {
        if (!ofirst) os << ",";
        ofirst = false;
        os << "{\"op\":\"" << ir::ir_op_name(static_cast<ir::IrOp>(kv.first))
           << "\",\"count\":" << kv.second << "}";
    }
    os << "]}}";
}

} // namespace effects
} // namespace analysis
