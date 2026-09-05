/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/effects/ir_effects.h
 * @brief Motor IR -> SemanticEffects.  Es el UNICO motor de efectos del caso
 *        principal: el asm lifteado ya es IR normal y pasa por aqui como
 *        cualquier otra instruccion.  Da (a) el efecto local de una instruccion
 *        (con la memoria clasificada a AbstractLoc via un mini points-to sobre
 *        los def-use de la funcion), y (b) el agregado local de una funcion
 *        (fold seq dentro de bloque, join entre bloques).
 */
#ifndef ANALYSIS_EFFECTS_IR_EFFECTS_H
#define ANALYSIS_EFFECTS_IR_EFFECTS_H

#include "analysis/facts/ir_facts.h"
#include "analysis/effects/effects.h"
#include "analysis/facts/asm_bindings.h"
#include "analysis/memory/points_to.h"

#include <cstdint>
#include <map>
#include <vector>

namespace ir {
struct IrFunction;
struct IrInstr;
struct IrModule;
struct IrNativeEffects;
using IrValueId = uint32_t; // igual que la definicion en ssa_ir.h
} // namespace ir

namespace analysis {
namespace effects {

/// Clasifica el puntero @p ptr (value id) a una localizacion abstracta a partir
/// de los HECHOS (def-use) de la funcion: ALLOCA->Stack, alloc->Heap,
/// static->Global, parametro->ArgDerived, GEP/cast->recurse.  Unknown si no se
/// puede.  Consume @c analysis::IrFacts (NO reconstruye el def-use).
AbstractLoc classify_ptr(const ir::IrFunction &fn,
                         const analysis::IrFacts &facts, ir::IrValueId ptr);

/// Registro de LAGUNAS de precision: hace VISIBLE donde el motor tuvo que subir
/// al efecto TOP y por que.  Permite reportar (a) que IrOps faltan por modelar
/// (cobertura -> mejorar el motor) y (b) donde la opacidad es fundamental
/// (FFI/dinamico -> oportunidades de optimizacion que solo un cambio de codigo
/// del usuario desbloquea).  Sin esto, un top() a secas ocultaria ambos.
struct EffectGaps {
    std::map<int, uint32_t> unmodeled_ops; ///< IrOp (int) -> numero de veces.
    std::map<UnknownReason, uint32_t> by_reason; ///< motivo -> numero de veces.
    uint32_t total_top = 0;                      ///< sitios que subieron a top.
    /// Mnemonicos de asm que la tabla no sabe explicar -> numero de veces.
    ///
    /// Sin el nombre, una laguna no se puede cerrar: "hay 2 instrucciones
    /// desconocidas" no dice cual anadir.  Y cerrarlas es justo la disciplina
    /// del analizador de asm -- la tabla crece bajo demanda --, asi que el dato
    /// tiene que llegar hasta aqui.
    std::map<std::string, uint32_t> mnemonicos_desconocidos;
    /// Funciones nativas de las que no se sabe que hacen -> numero de veces.
    ///
    /// NO toda llamada nativa es una caja negra: muchas son del propio
    /// proyecto y se sabe perfectamente lo que hacen.  Nombrarlas es lo que
    /// permite declararlas -- hoy en la tabla de nativas conocidas, manana
    /// desde el propio lenguaje en las `extern` y las syscall.
    std::map<std::string, uint32_t> nativas_desconocidas;

    void record(int op, UnknownReason why) {
        ++total_top;
        ++by_reason[why];
        if (reason_is_gap(why)) ++unmodeled_ops[op];
    }
    /// Apunta un mnemonico que no esta en la tabla.
    void record_mnemonico(const std::string &m) {
        ++mnemonicos_desconocidos[m];
    }
    /// Apunta una llamada a codigo que NO esta en el programa.
    ///
    /// Cuenta como sitio en el maximo igual que los demas: el cierre acaba de
    /// subir ahi por no tener nada que analizar.  Sin contarlo, el informe
    /// decia "ninguna laguna" y se callaba el nombre.
    void record_nativa(const std::string &f) {
        ++nativas_desconocidas[f];
        ++total_top;
        ++by_reason[UnknownReason::UnknownFFI];
    }
    bool empty() const { return total_top == 0; }
};

/// Lo declarado sobre las funciones NATIVAS del programa, por nombre "lib:fn".
///
/// Apunta a las declaraciones que viven en los modulos (que sobreviven al
/// analisis), no copias: la declaracion tiene un solo sitio.
using NativeDecls = std::map<std::string, const ir::IrNativeEffects *>;

/// Recoge las declaraciones de todos los modulos del programa.
NativeDecls collect_native_decls(const std::vector<const ir::IrModule *> &mods);

/// Quien va a EJECUTAR el IR que se analiza.
///
/// Un efecto no es una propiedad del IR a secas: una misma op baja distinto en
/// cada backend, y varias solo existen porque hay un runtime detras.  Decir
/// "esta funcion es pura" sin decir para quien es decir a medias.
enum class Backend : uint8_t {
    Vm = 0, ///< Interprete: cada op es una instruccion de la maquina virtual.
    Jit,    ///< Igual semantica que Vm; el codigo es nativo.
    Aot, ///< Nativo standalone: lo que necesita runtime pasa por libvesta_rt.
};

const char *backend_name(Backend b);

/// Entorno del analisis: lo que hay que saber ADEMAS del IR para responder.
///
/// Va agrupado a proposito.  Son los ejes del modelo -- para quien se compila y
/// que se sabe de lo ajeno --, y crecera; pasarlos sueltos convertiria cada eje
/// nuevo en un parametro mas en cada firma de la cadena.
struct EffectEnv {
    Backend backend = Backend::Vm;
    const NativeDecls *decls = nullptr;
    /**
     * @brief Las ligaduras de asm de la funcion, YA calculadas.
     *
     * De que valor del programa habla cada operando de un bloque de asm es un
     * hecho de la FUNCION, no de la instruccion: no cambia mientras la funcion
     * no cambie.  Calcularlo aqui dentro significaba rehacerlo por cada
     * instruccion de asm y por cada consulta de efectos -- medido en el barrido
     * del DCE: 20 s de los 33 que tardaba compilar el programa entero, en
     * 106.665 llamadas.
     *
     * Nulo = "no las tengo": entonces se calculan, que es lo que se hacia
     * siempre.  Asi quien pregunte por efectos sin tener una base de hechos
     * montada sigue funcionando igual.
     */
    const AsmBindingFacts *asm_bindings = nullptr;
    /**
     * @brief Los rangos de la funcion, YA calculados.
     *
     * Mismo caso que @ref asm_bindings, y por la misma razon: entre que dos
     * numeros esta un valor es un hecho de la FUNCION, no de la instruccion --
     * no cambia mientras la funcion no cambie.  Calcularlo aqui dentro
     * significaba recorrer la funcion ENTERA una vez por bloque de asm: medido
     * sobre un programa con mucho ensamblador, 16,8 s de los 26 que tardaba
     * compilarlo, en 1.000 llamadas.
     *
     * Nulo = "no los tengo": entonces se calculan, que es lo que se hacia
     * siempre.  Asi quien pregunte por efectos sin una base de hechos montada
     * sigue funcionando igual.
     */
    const analysis::RangeFacts *rangos = nullptr;
    /**
     * @brief De QUE funcion son los rangos de arriba.
     *
     * Sin esto, un puntero que se quedara apuntando a los rangos de otra
     * funcion daria respuestas incorrectas EN SILENCIO -- que es peor que
     * recalcularlos. Con el dueno anotado, usarlos donde no toca es imposible:
     * no coinciden y se recalculan, que es el comportamiento seguro.
     */
    const ir::IrFunction *rangos_de = nullptr;
};

/**
 * @brief Si la funcion lleva algun bloque de asm.
 *
 * Es la unica condicion bajo la que hace falta prestarle los rangos: el
 * analisis de un bloque de asm es lo unico que los consume, porque el ancho de
 * un acceso como `rep movsb` lo da un registro y hay que saber entre que dos
 * numeros esta.
 *
 * Calcularlos "por si acaso" para toda funcion cuesta mucho mas que lo que
 * ahorra: recorrer la funcion entera, por funcion y por vuelta del punto fijo,
 * para que nadie los mire.
 */
bool funcion_tiene_asm(const ir::IrFunction &fn);

/**
 * @brief Traduce el efecto de una funcion al SITIO donde se la llama.
 *
 * Una funcion describe lo que toca en terminos de SUS parametros: `memset`
 * escribe "lo que le apunta el primero, desde 0 hasta n".  Eso no se puede
 * juzgar dentro de ella -- el tamano de la region lo sabe quien llama --, y
 * hasta ahora se resolvia tirandolo: el efecto de una llamada se convertia en
 * "puede tocar cualquier cosa".  Aqui se hace lo otro: cada parametro se
 * sustituye por el argumento REAL y el efecto pasa a hablar de la memoria del
 * llamante, que es donde si se puede comprobar.
 *
 * Es el mismo mecanismo que ya se usa con las nativas declaradas ("escribe el
 * segundo argumento" -> memoria concreta), aplicado ahora a lo que el analisis
 * DEDUCE del cuerpo de una funcion Vesta.  Un mecanismo, dos fuentes.
 *
 * Lo que no se puede traducir se dice, no se disimula: la pila o el monton del
 * callee no se pueden nombrar desde aqui -- sus identificadores son suyos --,
 * asi que pasan a desconocido.  Lo global sigue siendo global.
 *
 * @param callee_eff Efecto (cierre) de la funcion llamada.
 * @param args       Argumentos del sitio de llamada, en orden.
 * @param pt         Points-to del LLAMANTE, para resolver cada argumento.
 * @return El mismo efecto, hablando de la memoria del llamante.
 */
/**
 * @struct EfectoEnLlamada
 * @brief Lo que una llamada toca de la memoria del llamante.
 *
 * NO es un @c LocSet cualquiera, y la diferencia importa: aqui @ref lee y
 * @ref escribe son las localizaciones que se PUDIERON traducir -- cada una es
 * memoria que la llamada toca de verdad --, y @ref completo dice si son todas.
 *
 * Se separan porque son dos preguntas distintas y mezclarlas pierde la mitad.
 * En el reticulo normal, una sola localizacion desconocida absorbe el conjunto
 * entero: basta con que el llamado toque su propia pila para que "escribe en
 * `buf`, dieciseis bytes mas alla" se convierta en "escribe en algun sitio", y
 * con eso ya no se puede comprobar nada.  Quien necesite una cota SUPERIOR
 * ("no toca nada mas que esto") tiene que mirar @ref completo; quien solo
 * necesite saber que esas SI las toca -- comprobar si caben, por ejemplo --
 * puede usarlas tal cual.
 */
struct EfectoEnLlamada {
    LocSet lee;     ///< lo que se pudo traducir de las lecturas.
    LocSet escribe; ///< lo que se pudo traducir de las escrituras.
    /// @c false si algo del llamado no se pudo nombrar aqui (su pila, su
    /// monton, o un efecto que ya venia sin acotar).
    bool completo = true;
};

/**
 * @brief Traduce el efecto de una funcion al SITIO donde se la llama.
 *
 * Ver @ref EfectoEnLlamada para lo que significa el resultado.
 *
 * @param callee_eff Efecto (cierre) de la funcion llamada.
 * @param args       Argumentos del sitio de llamada, en orden.
 * @param pt         Points-to del LLAMANTE, para resolver cada argumento.
 * @return Lo que toca, en memoria del llamante.
 */
EfectoEnLlamada instanciar_en_llamada(const SemanticEffects &callee_eff,
                                      const ir::IrOperands &args,
                                      const analysis::PointsTo &pt);

/// Efecto LOCAL de UNA instruccion IR (con completeness + motivo).  El asm
/// lifteado no es especial: llega como ADD/LOAD/STORE/... normales. INLINE_ASM/
/// ASM_MICRO (residuo opaco) se analizan aparte con tags.  @p pt es la tabla
/// points-to COMPARTIDA de la funcion (resuelve punteros a su localizacion);
/// el llamador la construye UNA vez (compute_points_to) y la reusa por instr.
/// @p env dice para QUE BACKEND se analiza y que se ha declarado de las
/// nativas: una CALLN a una nativa declarada deja de ser opaca y aporta su
/// efecto exacto, con la memoria resuelta en el sitio de llamada.
EffectAnalysisResult effects_of_instr(const ir::IrFunction &fn,
                                      const analysis::IrFacts &facts,
                                      const analysis::PointsTo &pt,
                                      const ir::IrInstr &ins,
                                      const EffectEnv &env = EffectEnv{});

/// Efecto LOCAL agregado de una funcion completa (fold de sus bloques).  Es el
/// `.local` del SemanticSummary; el `.closure` (interproc) lo anade la Fase 2.
/// @p gaps (si != null) acumula las lagunas de precision encontradas.
EffectAnalysisResult function_local_effects(const ir::IrFunction &fn,
                                            EffectGaps *gaps = nullptr,
                                            const EffectEnv &env = EffectEnv{});

} // namespace effects
} // namespace analysis

#endif // ANALYSIS_EFFECTS_IR_EFFECTS_H
