/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/alignment.h
 * @brief De cuanto es multiplo un valor: el hecho de la alineacion.
 *
 * Hay preguntas que un programa se hace en EJECUCION teniendo el compilador la
 * respuesta:
 *
 *     if ((((uintptr) dst) & 31) == 0)  memcpy_alineada(...);
 *     else                              memcpy_normal(...);
 *
 * Esa comparacion cuesta una rama en cada llamada, y muchas veces su resultado
 * es el mismo siempre -- porque el destino sale de una reserva que ya garantiza
 * como esta alineada.  Con el hecho, la comparacion se pliega y de las dos
 * ramas queda una sola.
 *
 * Y sirve para lo contrario, que es lo que costo caro: hay instrucciones que
 * EXIGEN su direccion alineada (`movdqa` y compania), y sin poder demostrarlo
 * lo unico que cabe es avisar.  Con esto se puede decidir: o se demuestra, o el
 * aviso pasa a ser un error con su prueba.
 *
 * El valor es siempre una POTENCIA DE DOS, y 1 significa "no se sabe nada" --
 * todo entero es multiplo de 1.  Nunca se devuelve una alineacion que no se
 * pueda justificar: quedarse corto solo pierde una optimizacion, pasarse deja
 * pasar un programa que revienta.
 */

#ifndef ANALYSIS_FACTS_ALIGNMENT_H
#define ANALYSIS_FACTS_ALIGNMENT_H

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/asa/fact.h" // vocabulario de Ambito: kBackend*
#include "ir/ssa_ir.h"

namespace analysis {

/**
 * @struct AlignmentFacts
 * @brief Alineacion demostrable de cada valor de una funcion.
 */
struct AlignmentFacts {
    /// Por valor: el MODULO del que se conoce su resto.  Potencia de dos;
    /// 1 = no se sabe nada (todo entero es congruente con 0 modulo 1).
    std::vector<uint32_t> de_valor;
    /// Por valor: el RESTO respecto de ese modulo.
    ///
    /// Sin el resto solo se puede decir "quiza"; con el se puede decir que NO.
    /// `base + 1`, con `base` multiplo de 8, es congruente con 1 modulo 8: eso
    /// demuestra que no esta alineado a 16, y demostrarlo es la diferencia
    /// entre avisar y dar un error -- entre "no puedo comprobarlo" y "se que
    /// esta mal".
    std::vector<uint32_t> resto;

    /// Modulo conocido de @p v.  Fuera de rango -> 1 (no se sabe nada).
    uint32_t de(ir::IrValueId v) const noexcept {
        return v < de_valor.size() ? de_valor[v] : 1u;
    }
    /// Resto conocido de @p v respecto de @ref de.
    uint32_t resto_de(ir::IrValueId v) const noexcept {
        return v < resto.size() ? resto[v] : 0u;
    }

    /// @c true si @p v es multiplo de @p n con CERTEZA.
    bool multiplo_de(ir::IrValueId v, uint32_t n) const noexcept {
        return n != 0 && de(v) >= n && (de(v) % n) == 0 &&
               (resto_de(v) % n) == 0;
    }
    /// @c true si se sabe con CERTEZA que @p v NO es multiplo de @p n.
    ///
    /// No hace falta conocer @p v modulo @p n: basta con conocerlo modulo un
    /// DIVISOR suyo.  Si se sabe que `v` es congruente con 1 modulo 8, ya se
    /// sabe que no es multiplo de 16 -- todo multiplo de 16 es congruente con
    /// 0 modulo 8.  Exigir el modulo entero dejaba fuera justo el caso que
    /// interesa: una reserva alineada a 8 a la que se le suma uno.
    bool seguro_no_multiplo_de(ir::IrValueId v, uint32_t n) const noexcept {
        const uint32_t m = de(v);
        return n != 0 && m > 1 && (n % m) == 0 && resto_de(v) != 0;
    }
};

/**
 * @brief Calcula la alineacion demostrable de los valores de @p fn.
 *
 * Las reglas son las de la aritmetica, no una lista de casos:
 *
 *   - una constante es multiplo de la mayor potencia de dos que la divide;
 *   - una reserva lo es de lo que garantice quien reserva;
 *   - una SUMA es multiplo del maximo comun divisor de sus dos partes -- que
 *     con potencias de dos es la menor de las dos;
 *   - multiplicar o desplazar MULTIPLICA la alineacion;
 *   - un PHI vale lo que su peor rama, porque cualquiera puede darse.
 *
 * @param fn Funcion a examinar.
 * @return Los hechos de alineacion de sus valores.
 */
AlignmentFacts compute_alignment(const ir::IrFunction &fn);

/**
 * @enum Universo
 * @brief Hasta donde alcanza lo que se ha podido observar de una funcion.
 *
 * Es la pregunta previa a cualquier resumen entre funciones, y responderla mal
 * no da un resultado peor: da uno FALSO.  Juntar lo que aportan los sitios de
 * llamada que se ven solo describe lo que le llega a una funcion si no hay
 * otros, y eso depende de quien pueda alcanzarla.
 */
enum class Universo : uint8_t {
    /// Se puede llamar desde fuera de lo que se esta mirando.  No haber visto
    /// una llamada NO significa que no exista, asi que no se afirma nada.
    Abierto,
    /// Todas las llamadas posibles estaban a la vista y no habia ninguna.  Esto
    /// no es ignorancia: es haber DEMOSTRADO que nadie la llama, y de un cuerpo
    /// que no se ejecuta no hay nada que comprobar.
    CerradoSinLlamantes,
    /// Todas las llamadas posibles estaban a la vista y son estas.  Lo que
    /// aportan es todo lo que le llega.
    CerradoConLlamantes,
};

/**
 * @struct AlignmentSummaries
 * @brief Lo que se sabe de los PARAMETROS de cada funcion del modulo.
 *
 * Sin esto, el hecho se para en la frontera de la funcion: dentro de
 * `void f(u8* dst)` no se sabe nada de `dst`, aunque TODAS las llamadas le
 * pasen una direccion cuya alineacion se conoce.  Y ahi es donde hace falta,
 * porque el asm que exige alineacion suele estar dentro de una funcion que
 * recibe el destino, no donde se reserva.
 *
 * El resumen es el ENCUENTRO de lo que aportan todas las llamadas: un
 * parametro vale lo que su peor sitio de llamada, porque cualquiera puede
 * darse.  Pero antes de juntarlas hay que poder decir que son TODAS las que
 * hay -- ver @ref Universo --: una funcion que alguien puede llamar desde otro
 * modulo no se resume, por muchas llamadas que se le vean aqui.
 */
struct AlignmentSummaries {
    /// Por funcion: modulo y resto conocidos de cada parametro.
    struct Param {
        uint32_t modulo = 1;
        uint32_t resto = 0;
    };
    /// Lo que se sabe de una funcion: hasta donde se ha visto, y que le llega.
    struct Resumen {
        Universo universo = Universo::Abierto;
        /// Vacio salvo en @ref Universo::CerradoConLlamantes.
        std::vector<Param> params;
        /**
         * @brief Lo que la funcion GARANTIZA del valor que devuelve.
         *
         * Es la otra mitad, y faltaba.  Con solo los parametros el hecho viaja
         * hacia dentro -- lo que las llamadas le dan --, pero no hacia fuera:
         * el resultado de CUALQUIER llamada quedaba en "no se sabe", incluso
         * el de una funcion cuyo cuerpo esta a la vista y devuelve algo cuya
         * alineacion se demuestra sola.
         *
         * El caso que lo pedia era el asignador, y por eso importa que esto NO
         * mire nombres: reconocer `malloc` habria resuelto ese caso y ninguno
         * mas, y ademas habria atado el analisis a una convencion -- un
         * asignador propio, un envoltorio, una funcion que devuelve el campo de
         * un objeto alineado, no se llaman de ninguna forma en particular.  Se
         * mira el CUERPO, asi que sirve para cualquier funcion.
         *
         * El encuentro de todos los `ret`: la funcion garantiza lo que
         * garantiza su peor salida, porque cualquiera puede darse.
         */
        Param retorno;
        /// Si @ref retorno dice algo.  Falso cuando no hay cuerpo que mirar
        /// (nativa) o cuando sus salidas no coinciden en nada.
        ///
        /// Es una condicion DISTINTA de @ref universo: para el retorno hace
        /// falta ver el CUERPO, no los llamantes.  Una funcion publica que
        /// cualquiera puede llamar sigue devolviendo lo mismo.
        bool retorno_valido = false;
    };
    std::unordered_map<std::string, Resumen> por_funcion;

    /// Lo que se sabe de @p nombre, o nullptr si no hay entrada (equivale a
    /// universo abierto: no se afirma nada).
    const Resumen *buscar(const std::string &nombre) const {
        auto it = por_funcion.find(nombre);
        return it == por_funcion.end() ? nullptr : &it->second;
    }
    /// Universo de @p nombre; abierto si no hay entrada.
    Universo universo_de(const std::string &nombre) const {
        const Resumen *r = buscar(nombre);
        return r == nullptr ? Universo::Abierto : r->universo;
    }
};

/**
 * @brief Resume que se sabe de los parametros de cada funcion del modulo.
 *
 * @param mod Modulo completo: hacen falta TODAS las llamadas.
 * @param programa_cerrado @c true cuando lo que se esta construyendo es el
 *        programa ENTERO (un ejecutable): entonces nadie de fuera puede llamar
 *        a nada y hasta una funcion publica tiene sus llamantes a la vista.
 *        @c false al construir una libreria o al mirar un modulo suelto: ahi
 *        solo se cierra lo privado.  Se pasa EXPLICITO porque no es una
 *        propiedad del IR sino de lo que se esta produciendo con el, y de eso
 *        depende que el mismo fichero de una respuesta u otra.
 * @return Los resumenes; una funcion sin entrada es una de la que no se puede
 *         afirmar nada.
 */
AlignmentSummaries compute_alignment_summaries(const ir::IrModule &mod,
                                               bool programa_cerrado);

/**
 * @brief Como @ref compute_alignment, sembrando los parametros con @p resumen.
 *
 * Es la misma cuenta con mejor punto de partida: los parametros dejan de valer
 * "no se sabe nada" y pasan a valer lo que dicen sus sitios de llamada.
 *
 * @param fn Funcion a examinar.
 * @param resumen Resumenes del modulo, o nullptr para no sembrar nada.
 * @return Los hechos de alineacion de sus valores.
 */
/**
 * @brief Como @ref compute_alignment, pero pudiendo mirar la DISPOSICION real
 *        de los datos estaticos del modulo.
 *
 * Aqui esta la diferencia entre este compilador y uno tradicional.  En uno
 * tradicional la direccion final de un dato la decide un enlazador ajeno, asi
 * que lo unico afirmable es la garantia generica del formato -- 8 bytes -- y
 * cualquier exigencia mayor queda en "no puedo probarlo".
 *
 * Aqui el enlazador es NUESTRO: de cada dato se conoce su desplazamiento dentro
 * de la seccion (@c StaticDataStore::Entry::byte_offset) y con que alineacion
 * se coloca la seccion.  Con esas dos cosas la alineacion real es
 * `mcd(alineacion de la seccion, desplazamiento)`, que es un NUMERO, no una
 * cota.  Quedarse en la garantia generica seria renunciar a lo que si se sabe.
 *
 * @param mod Modulo al que pertenece @p fn.  Nulo = como antes: de un dato
 *        estatico solo se afirma la garantia por defecto.
 */
/**
 * @brief Alineacion GARANTIZADA del bloque de globales en memoria host.
 *
 * No es una estimacion ni un deseo: es la alineacion con la que ese bloque se
 * reserva.  Vive aqui, y no donde se reserva, porque quien la necesita son los
 * dos lados -- quien reserva y quien razona sobre el resultado -- y si cada uno
 * llevara su numero podrian separarse sin que nada fallara: el analisis
 * afirmaria una alineacion que la reserva ya no da, y eso no da error, da
 * memoria mal leida.  Con una sola definicion, cambiarla los mueve a la vez.
 *
 * @see Executable::gdata_host, que la cumple y lo comprueba al compilar.
 */
/// 64 no es un numero redondo elegido por gusto: es el MAYOR de los que exigen
/// las arquitecturas que se soportan.  AVX-512 pide 64 en sus accesos
/// alineados, la linea de cache de x86-64 y de arm64 mide 64, SSE pide 16 y
/// NEON 16.  Cumplir el mayor cumple todos a la vez, asi que el bloque vale
/// para cualquier destino sin reservarlo distinto en cada uno.  Subirlo cuando
/// entre una ISA que pida mas -- SVE con vectores mas largos -- es cambiar esta
/// linea; bajarlo es romper en silencio la ISA que pedia mas.
static constexpr uint32_t kAlineacionBloqueGlobales = 64;

/**
 * @brief Con que alineacion se coloca la seccion de datos EN ESTE AMBITO.
 *
 * Es EL criterio, no una copia suya.  Lo usan los dos lados -- quien afirma el
 * hecho en el ASA y quien lo consume para probar una alineacion --, y esta
 * aqui por eso: si cada uno llevara el suyo serian dos criterios, y podrian
 * separarse sin que nada fallara.  Uno afirmaria lo que el otro ya no cumple.
 *
 * @param backend Uno de @c asa::kBackend*.  Vacio = sin decidir.
 * @return La alineacion garantizada, o 0 si en ese ambito NO SE SABE -- que no
 *         es lo mismo que "no esta alineado": es que no se puede afirmar, y
 *         quien pregunte debe quedarse con la garantia generica.
 */
/**
 * @brief Alineacion del payload que entrega el asignador EN ESTE AMBITO.
 *
 * Tampoco es una propiedad del programa: cada destino usa un asignador
 * distinto, y no tienen la misma disposicion interna.
 *
 *   - Nativo: `stdlib/vx/vx_mem.vx`, cabecera de 16, asi que el payload queda
 *     alineado a 16 y `movdqa` se puede DEMOSTRAR sobre memoria de monton.
 *   - Maquina: el de C++ (@c gc::RawAllocator), cabecera de 8.  Su camino
 *     rapido lo INLINEA el JIT, asi que subirlo es otro cambio con su propia
 *     medicion -- y hasta que se haga, afirmar 16 aqui seria mentir.
 *
 * Que los dos numeros discrepen no es un descuido: es lo que hay, y por eso se
 * dice en vez de promediarlo a la baja o darlo por igual.
 *
 * @return La alineacion garantizada del payload de una reserva pequena.
 */
inline uint32_t alineacion_payload_reserva(const char *backend) {
    (void)backend;
    /* 16 en los dos, por caminos distintos:
     *
     *   - Maquina y JIT: `gc::RawAllocator` NO lleva cabecera.  Trocea un
     *     chunk de pagina en slots del tamano de la clase -- 16, 32, 64...,
     *     potencias de dos --, asi que el payload cae alineado A SU CLASE, que
     *     es 16 lo mas bajo.  Se afirma 16 y no la clase porque el tamano
     *     exacto no siempre se conoce aqui; cuando se conozca, se puede
     *     afinar y sera MAS, nunca menos.
     *   - Nativo: `vx_mem.vx` lleva cabecera de 16 y avanza a saltos
     *     multiplos de 16, con lo que el payload queda igual de alineado.
     *
     * Antes se afirmaba 8, que en la maquina era quedarse corto por un factor
     * de dos o mas -- y en el nativo era la verdad, hasta que se subio la
     * cabecera. */
    return 16;
}

inline uint32_t alineacion_seccion_datos(const char *backend) {
    if (backend == nullptr) return 0;
    /* Corriendo en la maquina el bloque lo reserva el cargador: el numero es
     * nuestro y es firme. */
    if (std::strcmp(backend, asa::kBackendVm) == 0 ||
        std::strcmp(backend, asa::kBackendJit) == 0)
        return kAlineacionBloqueGlobales;
    /* Y en el nativo NO se sabe aqui: las secciones caen en pagina por
     * defecto, pero un guion de enlazado puede colocarlas donde quiera y esa
     * direccion no tiene por que cumplir nada.  Cuando el guion llegue hasta
     * aqui, este 0 pasa a ser el numero que toque. */
    return 0;
}

AlignmentFacts compute_alignment(const ir::IrFunction &fn,
                                 const AlignmentSummaries *resumen,
                                 const ir::IrModule *mod,
                                 uint32_t garantia_seccion_datos,
                                 uint32_t cabecera_slab);

AlignmentFacts compute_alignment(const ir::IrFunction &fn,
                                 const AlignmentSummaries *resumen,
                                 const ir::IrModule *mod);

AlignmentFacts compute_alignment(const ir::IrFunction &fn,
                                 const AlignmentSummaries *resumen);

} // namespace analysis

#endif // ANALYSIS_FACTS_ALIGNMENT_H
