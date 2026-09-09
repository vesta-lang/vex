/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/manager/analysis_codec.h
 * @brief Lo COMUN de guardar un analisis, en un sitio.
 *
 * @par Por que existe
 * El primer analisis que se guardo trajo consigo su marca de formato, su
 * aritmetica de limites al leer y su disciplina de "armar aparte y entregar al
 * final".  El segundo copio las tres.  Eso es la Regla 1 del ASA rota en el
 * sitio mas tonto: un mecanismo que se redescubre en cada consumidor.
 *
 * Y no es solo repeticion.  Cada copia es una oportunidad de equivocarse en lo
 * mismo:
 *
 * - **Inventar una marca propia.**  Dos analisis con la misma marca leen los
 *   bytes del otro como suyos, que no da error: da un resultado inventado.
 *   Aqui la marca SALE DEL NOMBRE, asi que dos nombres distintos no pueden
 *   coincidir y nadie tiene que elegir un numero.
 * - **Fiarse de una cuenta que viene de disco.**  `resize(n)` con la `n` del
 *   fichero es reservar dieciseis gigas si pone cuatro mil millones.  La
 *   comprobacion contra lo que QUEDA se escribe una vez, aqui.
 * - **Entregar una estructura a medio llenar.**  Si los bytes se cortan, quien
 *   pregunta tiene que quedarse con lo que tenia y computar; recibir la mitad
 *   es recibir hechos que nadie afirmo.
 *
 * @par Que sigue siendo de cada analisis
 * QUE campos escribe y en que orden.  Eso no se puede compartir y no se
 * intenta: lo que se comparte es la envoltura y las comprobaciones.
 *
 * @par Como se anade uno
 *   1. Que no guarde punteros (indices y rehidratar lo que haga falta).
 *   2. Un nombre estable y una version PROPIA del formato -- propia para que
 *      cambiar uno no tire lo guardado de los demas.
 *   3. Dos funciones libres: escribir y leer, usando @ref write_analysis_header
 *      y @ref read_analysis_header, y los ayudantes de vector de aqui.
 *   4. Comprobar la COHERENCIA con lo que se esta mirando antes de entregar --
 *      cuantos valores tiene la funcion, su huella --: es una comprobacion
 *      INDEPENDIENTE de la clave del almacen, y la que convierte un choque de
 *      claves en un descarte en vez de en hechos de otra funcion.
 */
#ifndef VESTA_ANALYSIS_ANALYSIS_CODEC_H
#define VESTA_ANALYSIS_ANALYSIS_CODEC_H

#include "util/serialize.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace analysis {

/**
 * @brief Escribe la cabecera comun: marca derivada del nombre, y version.
 *
 * La marca no se elige: se DERIVA de @p name.  Asi ningun analisis tiene que
 * inventar un numero, y dos analisis distintos no pueden compartirla por
 * descuido -- que es la forma de fallar que importa aqui, porque leer los bytes
 * de otro no da error, da un resultado inventado.
 *
 * @param w      Donde escribir.
 * @param name   Nombre estable del analisis.
 * @param format Version del formato de ESE analisis.
 */
void write_analysis_header(util::ByteWriter &w, const char *name,
                           uint32_t format);

/**
 * @brief Comprueba la cabecera que escribio @ref write_analysis_header.
 *
 * @param r      De donde leer.
 * @param name   El analisis que CREE estar leyendo.
 * @param format La version que sabe interpretar.
 * @return @c false si los bytes no son de ese analisis o son de otra version.
 *         No es un error: es lo guardado por un compilador de antes, y se
 *         computa como siempre.
 */
bool read_analysis_header(util::ByteReader &r, const char *name,
                          uint32_t format);

/**
 * @brief Escribe un vector de datos PLANOS: la cuenta y luego los bytes.
 *
 * En bloque y no elemento a elemento.  No es un detalle de estilo: la primera
 * version iba por elementos y costaba mas que RECOMPUTAR el analisis, que es la
 * unica forma en que una cache puede hacer dano.  Lo mide
 * `tests/analysis/test_analysis_store.cpp`.
 *
 * @warning Escribe la representacion del ANFITRIoN (orden de bytes y tamano).
 * Es legitimo porque esto es una cache LOCAL cuya unica promesa es que releerla
 * salga mas barato que rehacer el trabajo -- a diferencia del fichero de
 * hechos, que es un artefacto que viaja entre maquinas --.  Si algun dia se
 * comparte entre maquinas, esto tiene que volverse portable.
 */
template <class T>
void write_pod_vector(util::ByteWriter &w, const std::vector<T> &v) {
    w.u32(static_cast<uint32_t>(v.size()));
    if (!v.empty()) w.raw(v.data(), v.size() * sizeof(T));
}

/**
 * @brief Lee lo escrito por @ref write_pod_vector, comprobando la cuenta.
 *
 * La cuenta viene de disco y NO se cree: se compara con lo que queda por leer.
 * Sin eso, un fichero estropeado que diga cuatro mil millones pide dieciseis
 * gigas antes de que nadie note nada.
 *
 * @return @c false si no cuadra; @p out queda en un estado cualquiera y quien
 *         llama tiene que descartar la estructura entera, no entregarla.
 */
template <class T>
bool read_pod_vector(util::ByteReader &r, std::vector<T> &out) {
    const uint32_t n = r.u32();
    if (!r.ok()) return false;
    if (static_cast<size_t>(n) * sizeof(T) > r.remaining()) return false;
    out.resize(n);
    if (n == 0) return true;
    return r.raw(out.data(), static_cast<size_t>(n) * sizeof(T));
}

/**
 * @brief Los CoDIGOS de un analisis, guardados una vez y referidos por indice.
 *
 * Un analisis que dice POR QUE no sabe algo lleva un @c const char* a un
 * literal estable en cada entrada.  Un puntero no viaja, y repetir la cadena
 * por entrada seria escribir "memory.comes_from_outside" miles de veces.
 *
 * Asi que las distintas se escriben UNA vez y cada entrada guarda su indice.
 * Al leer, cada cadena distinta se interna en la reserva de nombres del
 * proceso, que da un puntero estable para toda su vida.
 *
 * @par Por que no vale la tabla del fichero de hechos
 * Aquella canoniza contra los nombres que los productores dan de alta, porque
 * alli un hecho tiene que reconocerse como del MISMO productor.  Aqui no hay
 * productores que registrar: son codigos de un dominio, y basta con que el
 * puntero sea estable y la cadena la misma.
 */
class CodeTable {
  public:
    /// El indice de @p code, dandolo de alta si es nuevo.  Al ESCRIBIR.
    uint32_t index_of(const char *code);
    /// Emite las cadenas recogidas.  Al ESCRIBIR, despues de las entradas.
    void write(util::ByteWriter &w) const;

    /**
     * @brief Lee la tabla y deja punteros ESTABLES en @p out.  Al LEER.
     *
     * Cada cadena distinta se interna una sola vez -- internar toma un cerrojo,
     * asi que hacerlo por entrada seria pagarlo miles de veces por la misma
     * respuesta --.
     *
     * @return @c false si los bytes no cuadran.
     */
    static bool read(util::ByteReader &r, std::vector<const char *> &out);

  private:
    std::vector<std::string> order_;
};

/**
 * @brief Cabe leer @p count elementos de @p bytes_each en lo que queda?
 *
 * Para los vectores que NO son de datos planos y hay que leer uno a uno: la
 * misma comprobacion, escrita una vez.  @p bytes_each es el MINIMO que ocupa un
 * elemento, no su tamano exacto -- basta para descartar una cuenta imposible,
 * que es lo que se quiere.
 */
inline bool fits_in(const util::ByteReader &r, uint32_t count,
                    size_t bytes_each) {
    return static_cast<size_t>(count) * bytes_each <= r.remaining();
}

} // namespace analysis

#endif // VESTA_ANALYSIS_ANALYSIS_CODEC_H
