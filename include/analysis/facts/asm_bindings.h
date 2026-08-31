/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/asm_bindings.h
 * @brief De que valor del programa habla cada operando de un bloque de asm.
 *
 * El analisis del asm razona sobre TEXTO, y en el texto un operando se llama
 * `$0` o `rdi`.  El resto del compilador razona sobre VALORES.  Entre las dos
 * cosas hay un camino -- marcador, ligadura, hueco de la variable, lo que se
 * guardo en el -- y ese camino es lo que hay aqui.
 *
 * Existe porque estaba escrito TRES veces: en el modelo de efectos (para decir
 * que memoria toca un bloque en vez de "cualquiera"), en el eliminador de
 * escrituras muertas, y otra vez al comprobar lo que una instruccion EXIGE.
 * Tres copias del mismo recorrido es, tarde o temprano, tres respuestas
 * distintas a la misma pregunta.
 *
 * Lo que NO hace: interpretar.  No dice si un acceso es seguro, ni cuanto mide
 * el operando (eso lo sabe la base de instrucciones, que conoce cada ISA), ni
 * que deberia hacer nadie con ello.  Responde una sola pregunta -- de que
 * valor habla este operando -- y quien pregunta decide.
 *
 * Y nunca elige a ciegas: la lista de ligaduras es de TODA la funcion, asi que
 * dos variables de ambitos distintos pueden usar el mismo registro.  Se
 * devuelven las dos y decide quien pregunta, que es el unico que sabe si le
 * vale con saber que fue "una de estas".
 */

#ifndef ANALYSIS_FACTS_ASM_BINDINGS_H
#define ANALYSIS_FACTS_ASM_BINDINGS_H

#include <string>
#include <vector>

#include "analysis/asa/fact.h"          // UnknownReason: por que no se supo
#include "analysis/facts/value_range.h" // acotar lo que no es constante
#include "ir/ssa_ir.h"
#include "vx/asm/asm_analyze.h" // la extension que describe el bloque

namespace analysis {

/**
 * @struct LigaduraAsm
 * @brief Un operando de asm, resuelto hasta el valor del que habla.
 */
struct LigaduraAsm {
    /// Como lo nombra el CUERPO: @c "$N" para los que elige el compilador, o
    /// el registro en forma canonica (@c "rax") para los fijos.  Es la clave
    /// por la que pregunta quien viene del texto.
    std::string marcador;
    /// Clase con la que se declaro (@c "reg", @c "xmm", @c "rax"...).  Dice
    /// cuanto MIDE el operando; traducirla a bits es cosa de la base de
    /// instrucciones, que conoce los registros de cada arquitectura.
    std::string clase;
    /// Hueco de la variable ligada (el @c ALLOCA).
    ir::IrValueId hueco = ir::IR_NO_VALUE;
    /// Valor que contiene ese hueco, o @c ir::IR_NO_VALUE si no se puede
    /// afirmar cual es (mas de una escritura -> depende del camino).
    ir::IrValueId valor = ir::IR_NO_VALUE;
};

/**
 * @struct AsmBindingFacts
 * @brief Las ligaduras de asm de una funcion, resueltas y consultables.
 *
 * Un mismo nombre puede tener VARIAS ligaduras: la lista es de toda la funcion,
 * asi que dos variables de ambitos distintos pueden usar el mismo registro. Eso
 * NO se resuelve tirando lo que se sabe de cada una -- cada ligadura conserva
 * su hueco y su contenido --, porque hay dos preguntas distintas y solo una
 * necesita saber cual es:
 *
 *   - "de que valor habla este operando" exige identidad: con dos candidatas no
 *     se puede afirmar nada de una en concreto -> @ref unica;
 *   - "que huecos puede haber tocado este bloque" no la exige: sirven TODAS,
 *     porque nombrar de mas es conservador y correcto -> @ref candidatas.
 *
 * Colapsar las dos en un "no se sabe" hacia que un bloque de asm con dos
 * variables en el mismo registro se volviera una barrera total, teniendo a mano
 * la lista exacta de lo que podia tocar.
 */
struct AsmBindingFacts {
    /// Ordenadas por marcador: la busqueda es binaria sobre memoria contigua.
    /// Son unas pocas por funcion, y estan en el camino de cada bloque de asm.
    std::vector<LigaduraAsm> ligaduras;

    /**
     * @struct Candidatas
     * @brief Las ligaduras que responden a un nombre, contiguas en memoria.
     */
    struct Candidatas {
        const LigaduraAsm *datos = nullptr;
        size_t n = 0;
        const LigaduraAsm *begin() const noexcept { return datos; }
        const LigaduraAsm *end() const noexcept { return datos + n; }
        bool empty() const noexcept { return n == 0; }
        size_t size() const noexcept { return n; }
    };

    /**
     * @brief Todas las ligaduras que responden a @p marcador.
     *
     * @param marcador @c "$N" o registro canonico, tal como sale del analisis
     *                 del texto.
     * @return El rango de candidatas; vacio si ninguna responde a ese nombre.
     */
    Candidatas candidatas(const std::string &marcador) const noexcept;

    /**
     * @brief La UNICA ligadura de la que habla @p marcador.
     *
     * @param marcador Nombre tal como sale del analisis del texto.
     * @return La ligadura, o @c nullptr si no hay ninguna o hay mas de una.
     *         Los dos casos se responden igual a proposito: quien necesita
     *         identidad no puede hacer nada distinto con "no hay" que con "hay
     *         varias", y quien SI puede tratarlas todas usa @ref candidatas.
     */
    const LigaduraAsm *unica(const std::string &marcador) const noexcept;
};

/**
 * @brief Resuelve las ligaduras de asm de @p fn.
 *
 * @param fn Funcion a examinar.
 * @return Sus ligaduras; vacio si la funcion no tiene asm ligado.
 */
AsmBindingFacts compute_asm_bindings(const ir::IrFunction &fn);

/**
 * @struct ExtensionResuelta
 * @brief Hasta donde llega un acceso, ya en bytes concretos.
 */
struct ExtensionResuelta {
    int64_t desde = 0;    ///< primer byte tocado, contando desde la base.
    int64_t hasta = 0;    ///< uno mas alla del ultimo byte tocado.
    bool acotada = false; ///< se pudo poner un limite a los dos extremos.

    int64_t bytes() const { return hasta - desde; }

    /**
     * @brief POR QUE no se pudo acotar.  Solo vale con @c !acotada.
     *
     * Aqui la diferencia no es academica: esto es lo que convierte un
     * `rep movsb` de "toca memoria en algun sitio" en "toca como mucho tantos
     * bytes desde aqui", y eso es lo que despues se compara contra el tamano de
     * la region para decir si se SALE.  Cuando no se puede acotar, el usuario
     * necesita saber cual de estas cosas le pasa:
     *
     *   - falta la LIGADURA del operando -> `ShapeNotRecognized`, y ahi si se
     *     le puede decir que escribir: liga ese registro a una variable;
     *   - la ligadura esta y el VALOR no tiene cota -> `RuntimeDependent`, que
     *     es cosa del programa y se arregla con una precondicion;
     *   - el bloque no dijo ni cuanto mide el acceso -> no hay nada que acotar.
     *
     * Con un solo `false`, las tres se leian como "no se puede comprobar este
     * asm", que es justo el veredicto que hace que nadie lo arregle.
     */
    asa::UnknownReason reason = asa::UnknownReason::NotAsked;
    /// Codigo estable del caso EXACTO, del vocabulario de este dominio.
    const char *reason_code = "";
};

/**
 * @brief Pone limites a la extension de un acceso de asm.
 *
 * El analisis del bloque describe hasta donde llega un acceso como una
 * EXPRESION -- tantos bytes, a tanta distancia, repetido tantas veces -- donde
 * lo que no es constante viene NOMBRADO (`rcx`, `$2`).  Aqui se cierra el
 * circulo: cada nombre se lleva por su ligadura hasta el valor del programa, y
 * de ese se pregunta el rango.
 *
 * Es lo que convierte un `rep movsb` de "toca memoria en algun sitio" en "toca
 * como mucho tantos bytes desde aqui", que ya es algo que se puede comprobar
 * contra el tamano de la region.
 *
 * @param lig    Ligaduras del bloque (marcador -> valor).
 * @param rangos Rangos de los valores de la funcion.
 * @param ex     La expresion a acotar.
 * @return Los limites; @c acotada en false si alguno se queda sin poner.
 */
ExtensionResuelta resolver_extension(const AsmBindingFacts &lig,
                                     const RangeFacts &rangos,
                                     const vx::AsmBlockEffects::Extension &ex);

} // namespace analysis

#endif // ANALYSIS_FACTS_ASM_BINDINGS_H
