/**
 * @file hook_points.h
 * @brief Vocabulario de la instrumentacion en compilacion: los PUNTOS de
 *        `@Hook(...)` y los campos que cada uno puede ofrecer al gancho.
 *
 * Esta tabla es la UNICA fuente de verdad del vocabulario.  Vive aqui, junta,
 * por el mismo motivo que las variables de entorno viven en
 * `include/util/env_flags_table.h`: repartida por el codigo se convierte en
 * folclore -- nadie puede listarla, nadie sabe si esta completa, y las dos
 * copias divergen sin que nadie lo note.  Ya paso con las claves de `@Target`,
 * que estaban en dos sitios ya divergidos y donde una errata borraba codigo en
 * SILENCIO.
 *
 * De aqui salen tres cosas que de otro modo se escribirian tres veces: la
 * validacion del punto (una errata es un ERROR, no una instrumentacion que no
 * ocurre), la validacion de la firma que el gancho declara, y el texto de
 * "esto es lo que hay disponible" que acompanya al diagnostico.
 */

#ifndef VX_HOOK_POINTS_H
#define VX_HOOK_POINTS_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace vx {

/**
 * @brief Punto de instrumentacion de un `@Hook(<punto>)`.
 *
 * Deja sitio a la familia entera de ganchos (`alloc`, `panic`, `unwind`) sin
 * anadir palabras clave nuevas al lenguaje: solo entradas a esta tabla.
 */
enum class HookPoint : uint8_t {
    Enter = 0, ///< Al ENTRAR en la funcion, antes de su primera sentencia.
    Exit = 1,  ///< Al SALIR de la funcion, por su propio pie.
    /**
     * @brief Al ATERRIZAR tras una excepcion, en la funcion que la captura.
     *
     * Existe porque una excepcion NO sale por el epilogo: salta directamente
     * al `catch`, y las funciones atravesadas por el salto no ejecutan su
     * `exit`.  Medido en los tres modos con tres funciones anidadas y un
     * `throw` en la mas profunda: 3 entradas, 1 sola salida.
     *
     * La alternativa era llevar un contador de profundidad y rebobinarlo
     * solo, pero eso cobra en CADA llamada -- inaceptable en un mecanismo
     * cuyo fin es medir sin distorsionar.  Asi el camino normal no paga nada
     * y el gancho, que es quien sabe como lleva su pila, la rebobina hasta la
     * funcion que recibe el control.
     */
    Unwind = 2,
    Count = 3 ///< Centinela; no es un punto.
};

/** @brief Mascara de bits de @ref HookPoint, para decir "vale en estos". */
inline constexpr uint8_t hook_mask(HookPoint p) noexcept {
    return static_cast<uint8_t>(1u << static_cast<uint8_t>(p));
}

/** @brief Un punto de la tabla: su nombre en el fuente y que significa. */
struct HookPointInfo {
    const char *name; ///< Como se escribe en `@Hook(<name>)`.
    const char *desc; ///< Una linea, para el diagnostico.
};

/**
 * @brief Los puntos, indexados por @ref HookPoint (array plano, no un mapa).
 *
 * El orden DEBE coincidir con el del enum: se indexa por su valor.
 */
inline constexpr HookPointInfo kHookPoints[] = {
    {"enter", "al entrar en la funcion"},
    {"exit", "al salir de la funcion"},
    {"unwind", "al capturar una excepcion, tras el salto"},
};
static_assert(sizeof(kHookPoints) / sizeof(kHookPoints[0]) ==
                  static_cast<size_t>(HookPoint::Count),
              "kHookPoints debe tener una entrada por HookPoint");

/**
 * @brief Un campo que un punto puede pasarle al gancho.
 *
 * El gancho declara los parametros que QUIERE y el compilador rellena esos y
 * solo esos: se paga unicamente lo que se pide.  El emparejamiento es por
 * NOMBRE del parametro, que es lo que permite que la firma la decida el
 * usuario sin que haya dispatch alguno en ejecucion.
 */
struct HookFieldInfo {
    const char *name;  ///< Nombre del parametro que lo recibe.
    const char *type;  ///< Tipo que debe declarar el gancho.
    uint8_t points;    ///< Puntos donde este campo esta disponible.
    const char *desc;  ///< Una linea, para el diagnostico.
};

/**
 * @brief Los campos disponibles, por punto.
 *
 * `fn_id` es un identificador y no un puntero a la funcion a proposito: es un
 * inmediato (sin reubicacion, sin tabla de simbolos) y por tanto funciona en
 * `--target bare`, donde no hay tabla que consultar.  La traduccion a
 * fichero/linea/tramo la da el `.vxdbg`, que ya la guarda.
 */
inline constexpr HookFieldInfo kHookFields[] = {
    // En `unwind`, el fn_id es el de la funcion que CAPTURA -- que es
    // justo el punto hasta el que el gancho tiene que rebobinar.
    {"fn_id", "u32",
     hook_mask(HookPoint::Enter) | hook_mask(HookPoint::Exit) |
         hook_mask(HookPoint::Unwind),
     "identificador de la funcion instrumentada"},
    {"call_site", "u64",
     hook_mask(HookPoint::Enter) | hook_mask(HookPoint::Exit),
     "direccion de retorno: QUIEN llamo"},
    {"depth", "u32", hook_mask(HookPoint::Enter) | hook_mask(HookPoint::Exit),
     "profundidad de anidamiento de la llamada"},
    {"ret_value", "u64", hook_mask(HookPoint::Exit),
     "valor devuelto por la funcion"},
};

/** @brief Cuantos campos tiene la tabla. */
inline constexpr size_t hook_field_count() noexcept {
    return sizeof(kHookFields) / sizeof(kHookFields[0]);
}

/**
 * @brief Resuelve el nombre de un punto.
 * @param name Lo que el usuario escribio en `@Hook(<name>)`.
 * @param out  Recibe el punto si se reconocio.
 * @return true si el nombre es de la tabla; false si es una errata.
 */
inline bool hook_point_from_name(const std::string &name,
                                 HookPoint &out) noexcept {
    for (size_t i = 0; i < static_cast<size_t>(HookPoint::Count); ++i) {
        if (name == kHookPoints[i].name) {
            out = static_cast<HookPoint>(i);
            return true;
        }
    }
    return false;
}

/**
 * @brief Los puntos validos, para el mensaje de error.
 *
 * Se construye de la MISMA tabla, asi que un punto nuevo aparece en el
 * diagnostico sin que nadie tenga que acordarse de anadirlo.
 * @return Los nombres separados por coma, p.ej. "enter, exit".
 */
inline std::string hook_points_available() {
    std::string s;
    for (size_t i = 0; i < static_cast<size_t>(HookPoint::Count); ++i) {
        if (i) s += ", ";
        s += kHookPoints[i].name;
    }
    return s;
}

/**
 * @brief Busca un campo por nombre y comprueba que el punto lo ofrezca.
 * @param name  Nombre del parametro declarado por el gancho.
 * @param point Punto en el que se instala el gancho.
 * @return El campo, o nullptr si no existe o ese punto no lo ofrece.
 */
inline const HookFieldInfo *hook_field_for(const std::string &name,
                                           HookPoint point) noexcept {
    for (size_t i = 0; i < hook_field_count(); ++i) {
        if (name == kHookFields[i].name &&
            (kHookFields[i].points & hook_mask(point)) != 0u)
            return &kHookFields[i];
    }
    return nullptr;
}

/**
 * @brief Los campos que un punto ofrece, para el mensaje de error.
 * @param point Punto sobre el que se consulta.
 * @return Texto "nombre: tipo" separado por coma, en el orden de la tabla.
 */
inline std::string hook_fields_available(HookPoint point) {
    std::string s;
    for (size_t i = 0; i < hook_field_count(); ++i) {
        if ((kHookFields[i].points & hook_mask(point)) == 0u) continue;
        if (!s.empty()) s += ", ";
        s += kHookFields[i].name;
        s += ": ";
        s += kHookFields[i].type;
    }
    return s;
}

} // namespace vx

#endif // VX_HOOK_POINTS_H
