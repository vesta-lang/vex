/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/vx/test_vx_builtin_names.cpp
 * @brief Comprueba que reconocer un builtin por tabla da lo mismo que
 *        compararlo contra su nombre.
 *
 * El orden de la tabla y que coincida con el enum ya los verifica el
 * compilador con dos `static_assert`, asi que aqui no hace falta repetirlo.
 * Lo que el compilador NO puede comprobar es lo unico que importa de verdad:
 * que la busqueda encuentra cada nombre y devuelve el que corresponde, y que
 * NO encuentra lo que no es un builtin.
 *
 * El caso peligroso no es el nombre que no existe: es el que se parece.  Un
 * `print` con una letra de mas, un prefijo de otro builtin, un nombre con la
 * longitud de uno de la tabla pero distinto contenido -- ahi es donde un
 * comparador que mira la longitud antes que los bytes puede equivocarse --.
 *
 * Del reparto en familias pasa lo mismo: que sean DISJUNTAS lo garantiza el
 * compilador -- el reparto es un `switch`, y dos `case` iguales no compilan --,
 * asi que aqui solo se mira que sea util: que ninguna se haya quedado vacia y
 * que un builtin de cada una caiga donde debe.
 */
#include "vx/builtin_names.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_fallos = 0; ///< Cuantas comprobaciones han fallado.

/**
 * @brief Comprueba una condicion y deja constancia si no se cumple.
 *
 * @param cond Lo que tiene que ser cierto.
 * @param que  Que se estaba comprobando, para el mensaje.
 */
void check(bool cond, const std::string &que) {
    if (!cond) {
        std::printf("FALLO: %s\n", que.c_str());
        ++g_fallos;
    }
}

} // namespace

/**
 * @brief Punto de entrada del test.
 *
 * @return 0 si todo paso, 1 si hubo algun fallo.
 */
int main() {
    using vx::Builtin;
    using vx::builtin_from_name;
    using vx::builtin_name;

    /* Ida y vuelta sobre TODOS: el enum va de Unknown+1 a Count-1, y cada uno
     * tiene que tener texto, y ese texto tiene que devolver ese mismo valor.
     * Esto recorre la tabla entera sin escribir aqui los doscientos nombres,
     * que seria una tercera copia de la lista -- justo lo que se quito. */
    const auto primero = static_cast<uint16_t>(Builtin::Unknown) + 1;
    const auto ultimo = static_cast<uint16_t>(Builtin::Count);
    int vistos = 0;
    for (uint16_t v = static_cast<uint16_t>(primero); v < ultimo; ++v) {
        const auto b = static_cast<Builtin>(v);
        const std::string txt(builtin_name(b));
        check(!txt.empty(),
              "el builtin " + std::to_string(v) + " no tiene texto");
        if (txt.empty()) continue;
        check(builtin_from_name(txt) == b, "ida y vuelta de '" + txt + "'");
        ++vistos;
    }
    check(vistos > 200, "se esperaban mas de doscientos builtins, hay " +
                            std::to_string(vistos));

    /* Un nombre que no lo es no puede colarse. */
    check(builtin_from_name("") == Builtin::Unknown, "la cadena vacia");
    check(builtin_from_name("mi_funcion") == Builtin::Unknown, "nombre normal");

    /* Y los que se PARECEN, que es donde falla un comparador mal escrito:
     * prefijos, sufijos, y nombres de la misma longitud que uno real. */
    check(builtin_from_name("prin") == Builtin::Unknown, "prefijo de print");
    check(builtin_from_name("printl") == Builtin::Unknown,
          "prefijo de println");
    check(builtin_from_name("printlnn") == Builtin::Unknown,
          "println con letra de mas");
    check(builtin_from_name("qrint") == Builtin::Unknown,
          "misma longitud que print");
    check(builtin_from_name("printz") == Builtin::Unknown,
          "misma longitud que printf");
    check(builtin_from_name("PRINT") == Builtin::Unknown,
          "print en mayusculas");

    /* Los extremos de la tabla: el mas corto y el mas largo se reconocen, y
     * uno mas corto o mas largo que cualquiera se descarta sin buscar. */
    check(builtin_from_name("Ok") == Builtin::Ok, "el nombre mas corto");
    check(builtin_from_name("a") == Builtin::Unknown, "mas corto que ninguno");
    check(builtin_from_name(std::string(64, 'x')) == Builtin::Unknown,
          "mas largo que ninguno");

    /* Unas cuantas a mano, de familias distintas, para que un error de
     * indexado global no pase entre el ida-y-vuelta. */
    check(builtin_from_name("print") == Builtin::Print, "print");
    check(builtin_from_name("println") == Builtin::Println, "println");
    check(builtin_from_name("malloc") == Builtin::Malloc, "malloc");
    check(builtin_from_name("term_move") == Builtin::TermMove, "term_move");
    check(builtin_from_name("shared_malloc") == Builtin::SharedMalloc,
          "shared_malloc");
    check(builtin_from_name("None") == Builtin::None, "None (el de Optional)");

    /* Un builtin invalido no revienta al pedir su texto. */
    check(builtin_name(Builtin::Unknown).empty(), "Unknown no tiene texto");
    check(builtin_name(Builtin::Count).empty(), "Count no tiene texto");

    /* --- El reparto en familias ---
     *
     * Que las familias sean DISJUNTAS no hace falta comprobarlo aqui: el
     * reparto es un `switch` y dos `case` con el mismo valor no compilan.  Lo
     * que si conviene mirar es que el reparto sea util -- que ninguna familia
     * se haya quedado vacia por un corte mal hecho -- y que un builtin de cada
     * una caiga donde debe. */
    int por_familia[11] = {0};
    for (uint16_t v = static_cast<uint16_t>(primero); v < ultimo; ++v) {
        const auto fam = vx::builtin_family(static_cast<Builtin>(v));
        const auto i = static_cast<size_t>(fam);
        check(i < 11,
              "familia fuera de rango para el builtin " + std::to_string(v));
        if (i < 11) ++por_familia[i];
    }
    const char *nombres[11] = {
        "Other",     "Print",  "Runtime", "Concurrent", "Optional", "Reflect",
        "Ownership", "String", "Math",    "Introspect", "<sobra>"};
    for (int i = 1; i <= 9; ++i)
        check(por_familia[i] > 0,
              std::string("la familia ") + nombres[i] + " se quedo vacia");
    check(por_familia[10] == 0, "hay una familia que el test no conoce");

    /* Uno de cada, para que un reparto corrido no pase desapercibido. */
    using vx::builtin_family;
    using vx::BuiltinFamily;
    check(builtin_family(Builtin::Println) == BuiltinFamily::Print,
          "println -> Print");
    check(builtin_family(Builtin::TermMove) == BuiltinFamily::Print,
          "term_move -> Print");
    check(builtin_family(Builtin::Malloc) == BuiltinFamily::Runtime,
          "malloc -> Runtime");
    check(builtin_family(Builtin::Msgsend) == BuiltinFamily::Concurrent,
          "msgsend -> Concurrent");
    check(builtin_family(Builtin::Some) == BuiltinFamily::Optional,
          "Some -> Optional");
    check(builtin_family(Builtin::ForName) == BuiltinFamily::Reflect,
          "forName -> Reflect");
    check(builtin_family(Builtin::UniqueBox) == BuiltinFamily::Ownership,
          "unique_box -> Ownership");
    check(builtin_family(Builtin::StrConcat) == BuiltinFamily::String,
          "str_concat -> String");
    check(builtin_family(Builtin::Sqrt) == BuiltinFamily::Math, "sqrt -> Math");
    check(builtin_family(Builtin::Popcount) == BuiltinFamily::Math,
          "popcount -> Math");
    check(builtin_family(Builtin::FfiOpen) == BuiltinFamily::Runtime,
          "ffi_open -> Runtime");
    check(builtin_family(Builtin::Sizeof) == BuiltinFamily::Introspect,
          "sizeof -> Introspect");
    check(builtin_family(Builtin::FieldName) == BuiltinFamily::Introspect,
          "field_name -> Introspect");
    /* Preguntar por un tipo AL COMPILAR y preguntar EN MARCHA son familias
     * distintas, y es lo que mas se presta a confusion. */
    check(builtin_family(Builtin::GetField) == BuiltinFamily::Reflect,
          "getField pregunta EN MARCHA -> Reflect, no Introspect");

    /* Lo que no es de nadie, y lo que no es un builtin. */
    check(builtin_family(Builtin::Vacount) == BuiltinFamily::Other,
          "vacount no tiene familia propia");
    check(builtin_family(Builtin::Unknown) == BuiltinFamily::Other,
          "Unknown -> Other");
    check(builtin_family(Builtin::Count) == BuiltinFamily::Other,
          "Count -> Other");
    check(builtin_family(static_cast<Builtin>(60000)) == BuiltinFamily::Other,
          "un valor fuera de rango no se sale de la tabla");

    if (g_fallos == 0)
        std::printf("OK: %d builtins, ida y vuelta correcta; en familias "
                    "%d/%d/%d/%d/%d/%d/%d/%d/%d, sin familia propia %d\n",
                    vistos, por_familia[1], por_familia[2], por_familia[3],
                    por_familia[4], por_familia[5], por_familia[6],
                    por_familia[7], por_familia[8], por_familia[9],
                    por_familia[0]);
    else
        std::printf("%d comprobaciones fallidas\n", g_fallos);
    return g_fallos == 0 ? 0 : 1;
}
