/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file unroll.h
 * @brief Pase de desenrollado (unroll) de bucles GENERAL, a nivel SSA IR.
 *
 * Desenrolla bucles CONTADOS innermost por un factor U, dejando el bucle
 * original como REMAINDER (procesa las < U iteraciones sobrantes).  Vive en el
 * IR compartido -> beneficia a los 3 backends: el interprete amortiza el
 * overhead de despacho del bucle (branch + incremento del indice) y el JIT/AOT
 * exponen mas ILP (U cadenas independientes que el register-renaming y el
 * scheduler solapan).  Cubre por igual los bucles del vectorizador (variable de
 * induccion con stride = ancho del vector) y los bucles escalares (stride 1).
 *
 * Bucle contado REDUCIBLE de una salida y un latch (la forma canonica que
 * desenrollan los compiladores reales; los bucles no-canonicos se canonizan
 * antes, no aqui):
 *
 *      preheader -> H
 *      H:  phi_k(init desde preheader, next_k desde el latch);
 * cond=cmp.OP(iv,N); br.cond cond, body_entry, exit   // OP in {lt,le,ult,ule},
 * iv crece body: 1 o VARIOS bloques con control de flujo INTERNO arbitrario
 * (ifs, merges) que convergen en un unico LATCH; iv_next = iv + S (S const >
 * 0); latch: br H exit: usa valores loop-closed (las phi de H)
 *
 * Transformacion: clona el CUERPO COMPLETO (todos los bloques del bucle salvo
 * H) U veces, encadenando los valores loop-carried (el latch de la copia k
 * salta a la entrada de la copia k+1; el de la ultima vuelve al header
 * unrollado UH); guard `iv + (U-1)*S {<,<=} N` en UH; el bucle ORIGINAL queda
 * como REMAINDER.
 *
 * Usa @c analysis::LoopFacts (conocimiento centralizado de bucles).  Modular:
 * vive en su propio TU (ir_optimizer.cpp ya es monolitico).
 *
 * FACTOR AUTOMATICO (como GCC/LLVM, no fijo): por defecto (factor=0) el pase
 * ELIGE el factor por bucle segun metricas del cuerpo (numero de instrucciones,
 * loads/stores, calls, ramas internas) para equilibrar overhead vs tamano de
 * codigo / presion de registros:
 *      cuerpo <= 8 instr  -> x8   (bucle diminuto: el cmp/jne domina)
 *      cuerpo <= 20 instr -> x4
 *      cuerpo <= 40 instr -> x2
 *      si no              -> no desenrollar (evita reventar la I-cache)
 * Un `factor` explicito (>=2) fuerza ese valor (solo para pruebas/benchmark).
 *
 * @param fn      Funcion SSA a transformar (in situ).
 * @param factor  0 = automatico (recomendado); >=2 = forzar ese factor.
 * @return true si desenrollo al menos un bucle.
 *
 * Skippable con la variable de entorno @c VESTA_NO_UNROLL=1 (A/B testing).
 */
#ifndef IR_PASSES_UNROLL_H
#define IR_PASSES_UNROLL_H

namespace analysis {
namespace asa {
class FactStore;
} // namespace asa
} // namespace analysis

namespace ir {

struct IrFunction;

/**
 * @brief Desenrolla los bucles contados que compensen.
 *
 * @param fn     Funcion a transformar.
 * @param factor 0 = lo decide la politica.
 * @param facts  Donde DEJAR lo que se sepa de cada bucle antes de tocarlo, o
 *               nulo para no publicar nada.
 *
 * Lo segundo no es un extra: este pase reconoce el bucle, averigua cuantas
 * vueltas da y acto seguido lo REESCRIBE, con lo que ese conocimiento moria
 * con la transformacion que lo produjo -- despues ya no hay bucle que contar,
 * y quien preguntaba se encontraba "no se puede afirmar cuantas vueltas da"
 * sobre un bucle que el compilador tenia perfectamente contado --.
 *
 * Los hechos salen sellados en el momento `in-opt`: son ciertos del codigo que
 * habia AQUI, ni antes ni despues.  Y como el almacen viaja a disco, la
 * proxima compilacion puede reutilizarlos en vez de volver a deducirlos.
 */
bool ir_pass_unroll(IrFunction &fn, int factor = 0,
                    analysis::asa::FactStore *facts = nullptr);

} // namespace ir

#endif // IR_PASSES_UNROLL_H
