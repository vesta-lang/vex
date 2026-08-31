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
 * @file fmt_test.cpp
 * @brief Las dos propiedades que hacen fiable al formateador, comprobadas.
 *
 * Un formateador se juzga por dos cosas, y ninguna se puede prometer -- hay que
 * comprobarlas sobre codigo de verdad:
 *
 *     format(format(x)) == format(x)      idempotente
 *     tokens(format(x)) == tokens(x)      el programa NO cambia, solo su forma
 *
 * La segunda es la que impide que rompa codigo en silencio: si la lista de
 * tokens es la misma antes y despues, lo unico que se ha movido es espacio en
 * blanco.  Eso es exactamente `P2` del estandar de estilo.
 *
 * Corre sobre TODO el corpus (`examples_codes_vx/` y `stdlib/vx/`): mas de
 * quinientos ficheros escritos a mano, que son el codigo Vesta mas variado que
 * hay y por tanto la mejor prueba disponible.
 *
 * Uso:  ./test_vx_fmt [raiz_del_repositorio]
 */

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "vx/diagnostic.h"
#include "vx/fmt/fmt_internal.h"
#include "vx/fmt/width.h"
#include "vx/lexer.h"

namespace {

int g_passed = 0; ///< comprobaciones pasadas
int g_failed = 0; ///< comprobaciones fallidas

/**
 * @brief Comprueba una condicion y la cuenta.
 * @param cond  Lo que tiene que ser cierto.
 * @param what  Que se comprueba.
 * @param where Fichero al que se refiere, si aplica.
 */
void check(bool cond, const char *what, const std::string &where = "") {
    if (cond) {
        ++g_passed;
        return;
    }
    ++g_failed;
    std::printf("  FALLA %s%s%s\n", what, where.empty() ? "" : "  --  ",
                where.c_str());
}

/**
 * @brief Lee un fichero entero.
 * @param path Ruta.
 * @param out  [out] contenido.
 * @return Cierto si se pudo leer.
 */
bool read_file(const std::string &path, std::string &out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

/**
 * @brief Aplica las comprobaciones a un fichero.
 * @param path Ruta del .vx.
 */
void check_file(const std::string &path) {
    std::string source;
    if (!read_file(path, source) || source.empty()) return;

    /* 0) Trocear y volver a pegar tiene que dar el ORIGINAL, byte a byte.  Es
     *    lo que sostiene todo lo demas: si la trivia se recupera bien del
     *    texto, el formateador no puede perder un comentario. */
    std::string_view tail;
    std::string code;
    const std::vector<vx::fmt::Piece> pieces =
        vx::fmt::scan_pieces(source, path, tail, code);
    std::string rebuilt;
    rebuilt.reserve(source.size());
    for (const vx::fmt::Piece &p : pieces) {
        rebuilt.append(p.trivia);
        rebuilt.append(p.text);
    }
    rebuilt.append(tail);
    check(code.empty(), "el troceado no falla", path);
    check(rebuilt == source, "trocear y pegar devuelve el original", path);

    // 1) Formatear no puede fallar sobre codigo que ya compila.
    const vx::fmt::FormatResult one = vx::fmt::format(source, path);
    check(one.ok, "formatear no falla", path + (one.ok ? "" : ": " + one.code));
    if (!one.ok) return;

    // 2) Idempotencia: formatear lo ya formateado no cambia nada.
    const vx::fmt::FormatResult two = vx::fmt::format(one.text, path);
    check(two.text == one.text, "formatear es idempotente", path);

    /* 3) `P2`: el programa no cambia.  Esta es LA comprobacion, y usa la MISMA
     *    funcion que la salvaguarda de `format` -- no una propia --: cuando el
     *    test tenia su version, era mas debil y daba por bueno lo que el codigo
     *    rechazaba. */
    check(vx::fmt::same_program(source, one.text, one.rewrites),
          "formatear no cambia el programa", path);
}

/**
 * @brief Unicode: contar columnas no es contar bytes ni contar caracteres.
 *
 * Es la base de las dos reglas que MIDEN -- el limite de linea (`R3`) y la
 * alineacion (`R84`) --, asi que se fija aqui antes de que ninguna la use.
 *
 * Los literales van escapados byte a byte para que este fichero siga siendo
 * ASCII, como manda el proyecto.  Lo que se escribe con `\xNN` es exactamente
 * lo que un editor guardaria al teclear ese caracter.
 */
void check_unicode_width() {
    // Un ideograma chino (U+4F60): 3 bytes, 1 caracter, DOS columnas.
    const std::string ni = "\xe4\xbd\xa0";
    check(ni.size() == 3, "el ideograma ocupa tres bytes");
    check(vx::fmt::display_width(ni) == 2, "y DOS columnas, no tres ni una");

    // "Hola mundo" en chino: cuatro ideogramas, 12 bytes, OCHO columnas.
    const std::string hola = "\xe4\xbd\xa0\xe5\xa5\xbd\xe4\xb8\x96\xe7\x95\x8c";
    check(hola.size() == 12, "doce bytes");
    check(vx::fmt::display_width(hola) == 8, "y ocho columnas");

    // Un emoji (U+1F680): 4 bytes, DOS columnas.
    const std::string cohete = "\xf0\x9f\x9a\x80";
    check(cohete.size() == 4, "un emoji ocupa cuatro bytes");
    check(vx::fmt::display_width(cohete) == 2, "y dos columnas");

    // Una letra acentuada: 2 bytes, UNA columna.
    const std::string cafe = "caf\xc3\xa9";
    check(cafe.size() == 5, "cinco bytes para cuatro letras");
    check(vx::fmt::display_width(cafe) == 4, "y cuatro columnas");

    // Un acento COMBINANTE se pinta encima del anterior: cero columnas.
    const std::string combinado = "e\xcc\x81";
    check(combinado.size() == 3, "tres bytes");
    check(vx::fmt::display_width(combinado) == 1,
          "un acento combinante no ocupa columna propia");

    /* Un emoji compuesto con juntadores: la mujer programadora son tres puntos
     * de codigo -- mujer, ZWJ, ordenador --, once bytes, y se pinta como uno.
     * Sin contar el juntador a cero saldrian mas columnas de las que ocupa. */
    const std::string zwj = "\xf0\x9f\x91\xa9\xe2\x80\x8d\xf0\x9f\x92\xbb";
    check(vx::fmt::display_width(zwj) == 4,
          "el juntador de un emoji compuesto no ocupa");

    // Un tabulador avanza a la siguiente PARADA, no una anchura fija.
    check(vx::fmt::display_width("\t", 4, 0) == 4, "un tab desde la columna 0");
    check(vx::fmt::display_width("\t", 4, 1) == 3, "un tab desde la columna 1");
    check(vx::fmt::display_width("\t", 4, 3) == 1, "un tab desde la columna 3");
    check(vx::fmt::display_width("\t", 4, 4) == 4, "un tab desde la columna 4");

    /* ROBUSTEZ: UTF-8 mal formado.  Un editor que guardo a medias, o un fichero
     * en otra codificacion, no puede colgar al formateador ni hacerle leer
     * fuera del buffer: cada byte malo cuenta uno y se sigue. */
    const std::string roto = "a\xff\xfe"
                             "b";
    check(vx::fmt::display_width(roto) == 4,
          "el UTF-8 invalido cuenta byte a byte");
    const std::string cortado = "a\xe4\xbd"; // secuencia cortada por el final
    check(vx::fmt::display_width(cortado) >= 1,
          "una secuencia cortada no cuelga");

    // Y formatear un fuente con todo eso dentro no lo cambia.  Se compone con
    // las piezas de arriba para no tener que escapar nada mas aqui.
    const std::string fuente = "// " + hola +
                               "\n"
                               "i32 main() {\n"
                               "    string s = \"" +
                               cohete + " " + cafe +
                               "\";\n"
                               "    return 0;\n"
                               "}\n";
    const vx::fmt::FormatResult uni = vx::fmt::format(fuente, "<unicode>");
    check(uni.ok, "un fuente con chino y emojis se formatea");
    check(vx::fmt::same_program(fuente, uni.text), "y no cambia el programa");
}

/**
 * @brief Espaciado: lo inequivoco se arregla, lo ambiguo se respeta.
 *
 * Los dos primeros casos NO son de estilo: son de correccion.  Pegar dos
 * tokens que se funden en uno mas largo cambia el programa, y con `//` se lleva
 * por delante el resto de la linea.
 */
void check_spacing() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<espaciado>").text;
    };

    // Dos signos que se fundirian: NUNCA se pegan.
    const std::string resta = fmt("i32 f() { return a - -b; }\n");
    check(resta.find("--") == std::string::npos,
          "una resta de un negativo no se convierte en un decremento");

    // Dos palabras tampoco.
    const std::string dos = fmt("i32 f() { return x; }\n");
    check(dos.find("returnx") == std::string::npos,
          "dos palabras nunca quedan pegadas");

    // `R52` frente a `R33`: el espacio distingue el control de la llamada.
    const std::string control = fmt("i32 f() { if(c){ g(); } }\n");
    check(control.find("if (c)") != std::string::npos,
          "una palabra clave se separa de su parentesis");
    check(control.find("g()") != std::string::npos,
          "una llamada va pegada al suyo");

    // `R35` y `R63`: comas y punto y coma.
    const std::string comas = fmt("i32 f() { g( a , b ) ; }\n");
    check(comas.find("g(a, b);") != std::string::npos,
          "un espacio tras la coma, ninguno antes ni dentro del parentesis");

    // `R61`: los binarios inequivocos se separan.
    const std::string binario = fmt("i32 f() { bool k=a==b&&c!=d; }\n");
    check(binario.find("k = a == b && c != d;") != std::string::npos,
          "los operadores inequivocos llevan un espacio a cada lado");

    // `R62`: un signo va pegado a lo que niega.
    const std::string signo = fmt("i32 f() { i64 d = -a; }\n");
    check(signo.find("= -a;") != std::string::npos,
          "un signo va pegado a su operando");

    /* El `&` de TOMAR UNA DIRECCION y el de un `y` logico se escriben igual, y
     * el formateador tiene que distinguirlos: pegado a lo que sigue el
     * primero, con un espacio a cada lado el segundo.  Es lo unico que separa
     * `f(&v)` de `f(a & v)` al leerlo.
     *
     * Se comprueban los DOS en cada forma de lo que puede haber delante: si
     * solo se mirara uno, "arreglarlo" rompe el otro sin que nadie lo note --
     * que es exactamente lo que paso detras de un cast --. */
    const std::string amp =
        fmt("i32 f() { r = a&b; r = &a==&b; p = &arr[1]; r = arr[1]&3;\n"
            "p = &s.f; r = s.f&3; r = g(1)&3; r = g(&a); r = *p&3;\n"
            "r = (a)&b; r = a & &b; r &= 3; k = a==1&&b==2;\n"
            "r = g(a, &b); if (a&1) { r = 0; } r = k ? a&b : a; }\n");
    struct AmpCaso {
        const char *espera;
        const char *que;
    };
    static const AmpCaso amp_casos[] = {
        {"a & b", "entre dos nombres es un `y` logico"},
        {"&a == &b", "tras un `=` o un operador es una direccion"},
        {"&arr[1]", "delante de un indexado es una direccion"},
        {"arr[1] & 3", "detras de un indexado es un `y` logico"},
        {"&s.f", "delante de un campo es una direccion"},
        {"s.f & 3", "detras de un campo es un `y` logico"},
        {"g(1) & 3", "detras de una llamada es un `y` logico"},
        {"g(&a)", "como argumento es una direccion"},
        {"*p & 3", "detras de un deref es un `y` logico"},
        {"(a) & b", "detras de una AGRUPACION es un `y` logico"},
        {"a & &b", "los dos seguidos: logico y luego direccion"},
        {"r &= 3", "el compuesto no se parte"},
        {"a == 1 && b == 2", "el `y` logico doble NO se parte en dos"},
        {"g(a, &b)", "tras una coma es una direccion"},
        {"if (a & 1)", "dentro de una condicion es un `y` logico"},
        {"k ? a & b : a", "dentro de un ternario es un `y` logico"},
    };
    for (const AmpCaso &c : amp_casos)
        check(amp.find(c.espera) != std::string::npos, c.que, c.espera);

    /* Detras del `)` de un CAST empieza un valor, asi que lo que hay ahi es un
     * PREFIJO -- `(u64)&v` es una direccion, no un `y` logico --.
     *
     * Es lo unico que no puede decidir el espaciador por su cuenta: desde ahi
     * un `)` de cast y uno de agrupacion se ven igual, y `(v) - 1` SI es una
     * resta.  Por eso se comprueban los dos, o "arreglar" el primero rompe el
     * segundo sin que nadie lo note. */
    const std::string cast_prefijo =
        fmt("i32 f() { i64 v = 1; u64 b = (u64)&v; i64 c = (i64)*p;\n"
            "i64 d = (i64)-1; i64 e = (v) - 1; i64 g = (v + 1) & 3; }\n");
    check(cast_prefijo.find("(u64)&v") != std::string::npos,
          "tras un cast, `&` toma una direccion");
    check(cast_prefijo.find("(i64)*p") != std::string::npos,
          "tras un cast, `*` es un deref");
    check(cast_prefijo.find("(i64)-1") != std::string::npos,
          "tras un cast, `-` niega");
    check(cast_prefijo.find("(v) - 1") != std::string::npos,
          "tras una AGRUPACION, `-` sigue siendo una resta");
    check(cast_prefijo.find("(v + 1) & 3") != std::string::npos,
          "tras una AGRUPACION, `&` sigue siendo un `y` logico");

    // `R4`: la llave de apertura lleva un espacio delante.
    const std::string llave = fmt("i32 f(){ return 0; }\n");
    check(llave.find("f() {") != std::string::npos,
          "la llave de apertura va separada por un espacio");

    /* LO AMBIGUO SE RESUELVE, no se esquiva.  `Caja<i64>` y `a < b` son el
     * mismo par de tokens, y `i64* p` y `a * b` tambien: quien los distingue es
     * el pase que anota el papel de cada uno.  Estas comprobaciones son las que
     * impiden que esa parte se degrade a "no tocar". */
    const std::string generico =
        fmt("i32 f() { Caja < i64 > c = g<i64>(); }\n");
    check(generico.find("Caja<i64> c") != std::string::npos,
          "un argumento de tipo se pega, aunque viniera separado");
    check(generico.find("g<i64>();") != std::string::npos,
          "y tras cerrarlo, la llamada sigue pegada");

    const std::string comparacion = fmt("i32 f() { bool k = a<b && c>d; }\n");
    check(comparacion.find("a < b && c > d") != std::string::npos,
          "una comparacion con los mismos signos SI se separa");

    const std::string puntero = fmt("i32 f() { i64  *  p = & a; }\n");
    check(puntero.find("i64* p = &a;") != std::string::npos,
          "el asterisco se pega al tipo y se separa del nombre");
    const std::string usuario = fmt("i32 f() { Punto  *  q = &pt; }\n");
    check(usuario.find("Punto* q = &pt;") != std::string::npos,
          "tambien con un tipo del usuario, no solo con los primitivos");

    const std::string producto = fmt("i32 f() { i64 r = foo(a * b); }\n");
    check(producto.find("foo(a * b)") != std::string::npos,
          "y un producto con los mismos tokens sigue llevando espacios");

    /* Las colecciones son TIPOS del lenguaje, no identificadores: sin contarlas
     * como tales, un `HashMap<...>` no se reconoce como generico. */
    const std::string coleccion =
        fmt("i32 f() { HashMap<string, ArrayList<i64>> m = h(8); }\n");
    check(coleccion.find("HashMap<string, ArrayList<i64>> m") !=
              std::string::npos,
          "un generico anidado que cierra con >> se reconoce");
}

/**
 * @brief Los dos puntos son SEIS cosas distintas, y cada una se espacia igual.
 *
 * No se distinguen por lo que tienen al lado -- en `case Foo:` y en `a ? b : c`
 * el token de la izquierda puede ser el mismo -- sino por DONDE estan.  Estas
 * comprobaciones son las que impiden que ese contexto se pierda.
 */
void check_colon_uses() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<colon>").text;
    };

    // Herencia: espacios a los dos lados.
    check(fmt("class A:B { }\n").find("class A : B") != std::string::npos,
          "la herencia lleva espacios");

    // Ternario: espacios.  Y el `-1` sigue siendo un signo, no una resta.
    check(fmt("i32 f(i32 n) { return n<0?-1:1; }\n").find("n < 0 ? -1 : 1") !=
              std::string::npos,
          "el ternario lleva espacios y el signo se queda pegado");

    // Anulable: pegado al tipo.
    check(fmt("class A { public A? p; }\n").find("A? p;") != std::string::npos,
          "un tipo anulable va pegado");

    // Recorrido: espacios.
    check(
        fmt("i32 f() { for (i64 v:xs) t += v; }\n").find("for (i64 v : xs)") !=
            std::string::npos,
        "el recorrido lleva espacios");

    // Rama de un `match`: pegado delante.
    check(fmt("i32 f() { match (x) { case None:return 0; } }\n")
                  .find("case None: return 0;") != std::string::npos,
          "una rama va pegada delante y separada detras");

    // Restriccion: pegado delante.
    check(fmt("T f<T>(T a) where T:Comparable { return a; }\n")
                  .find("where T: Comparable") != std::string::npos,
          "una restriccion va pegada delante");

    // `R57`: una etiqueta va un nivel menos que el codigo.
    const std::string etiqueta =
        fmt("i32 f() {\n\tgoto salir;\nsalir:\n\treturn 0;\n}\n");
    check(etiqueta.find("\nsalir:\n") != std::string::npos,
          "una etiqueta de goto no se indenta con el codigo");
}

/**
 * @brief Las columnas: que se alinee lo que toca y NO lo que no (`R83`-`R88`).
 *
 * Lo segundo importa tanto como lo primero.  Un bloque que se come una linea en
 * blanco -- o que estira una linea por encima del limite -- es peor que no
 * alinear: quien escribe pierde el control de donde empieza y acaba un grupo.
 */
void check_alignment() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<align>").text;
    };

    // Tres declaraciones seguidas: tipo, nombre y `=` en columna.
    const std::string bloque = fmt("i32 f() {\n"
                                   "u8 contador = 0;\n"
                                   "i32 total = 0;\n"
                                   "unique<Buffer> datos = b();\n"
                                   "}\n");
    check(bloque.find("u8             contador = 0_u8;") != std::string::npos,
          "el tipo se estira hasta el mas largo del bloque");
    check(bloque.find("i32            total    = 0_i32;") != std::string::npos,
          "y el nombre tambien, para que el = quede en columna");

    /* `R83`: una linea en blanco ROMPE el bloque.  Es lo que le da el control a
     * quien escribe: para que dos cosas no se alineen, se separan. */
    const std::string roto = fmt("i32 f() {\n"
                                 "u8 contador = 0;\n"
                                 "i32 total = 0;\n"
                                 "\n"
                                 "i32 n = 1;\n"
                                 "}\n");
    check(roto.find("i32 n = 1_i32;") != std::string::npos,
          "tras una linea en blanco empieza otro bloque");

    // Una linea suelta no se alinea con nadie.
    check(fmt("i32 f() { i64 x = 1; }\n").find("i64 x = 1_i64;") !=
              std::string::npos,
          "una sola declaracion no se estira");

    /* `R86`: si estirar sacara alguna linea de las 80 columnas, el bloque se
     * queda sin alinear.  Un nombre larguisimo no puede empujar a sus vecinos
     * fuera del limite. */
    const std::string largo =
        fmt("i32 f() {\n"
            "u8 c = 0;\n"
            "unique<ConfiguracionDelUsuarioMuyLarga> configuracion_del_todo = "
            "unique_box(x);\n"
            "}\n");
    for (size_t i = 0, ancho = 0; i <= largo.size(); ++i) {
        if (i == largo.size() || largo[i] == '\n') {
            check(ancho <= 96, "ninguna linea se dispara al alinear");
            ancho = 0;
            continue;
        }
        ancho += (largo[i] == '\t') ? 4 : 1;
    }
}

/**
 * @brief Las formas que NO llevan `=`: bits y vistas (`R98`, `R99`).
 *
 * Un campo de bits y un campo de `@overlay` no tienen valor inicial, tienen
 * una anchura y un desplazamiento.  Alinearlos importa mas que en una
 * declaracion corriente: es lo que se compara contra la especificacion de un
 * formato binario, o lo que se suma para ver si los bits cuadran.
 */
void check_field_shapes() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<campos>").text;
    };

    // `R99`: los bits se alinean por sus dos puntos.
    const std::string bits = fmt("struct Flags {\n"
                                 "u32 a : 3;\n"
                                 "u32 b : 5;\n"
                                 "u32 rest : 16;\n"
                                 "}\n");
    check(bits.find("u32 a    : 3;") != std::string::npos,
          "los campos de bits se alinean por los dos puntos");
    check(bits.find("u32 rest : 16;") != std::string::npos,
          "y el mas largo fija la columna");

    // `R98`: una vista se alinea por su desplazamiento.
    const std::string vista = fmt("@overlay struct H {\n"
                                  "u16 e_magic @0x00;\n"
                                  "i32 e_lfanew @0x3C;\n"
                                  "}\n");
    check(vista.find("u16 e_magic  @0x00;") != std::string::npos,
          "los campos de una vista se alinean por el desplazamiento");
    check(vista.find("i32 e_lfanew @0x3C;") != std::string::npos,
          "y los offsets quedan en columna para poder compararlos");

    /* `R100`: un desplazamiento puede ser un BLOQUE que lo calcula.  Ese campo
     * no comparte columnas con los de offset literal -- su linea acaba en `{`,
     * no en `;` --, y alinearlos juntos estropearia la rejilla de los que si se
     * comparan entre si. */
    const std::string mixto = fmt("@overlay struct M {\n"
                                  "u32 a @0x00;\n"
                                  "u32 bbbb @0x0C;\n"
                                  "u8 nombre @offset {\n"
                                  "return parent<Pe>().t(this.a);\n"
                                  "};\n"
                                  "}\n");
    check(mixto.find("u32 a    @0x00;") != std::string::npos,
          "los de offset literal se siguen alineando entre si");
    check(mixto.find("u8 nombre @offset {") != std::string::npos,
          "y el que lleva bloque no se estira con ellos");

    // `R72`: una anotacion se separa de lo que anota, aunque viniera pegada.
    const std::string suelta = fmt("@overlay struct P { u32 a @0x00; }\n");
    check(suelta.find("@overlay\nstruct P") != std::string::npos,
          "una anotacion pegada se pone en su propia linea");

    /* `R101`: los parentesis de una anotacion SI se reparten aunque no lleven
     * comas -- es el unico sitio por donde esa linea se acorta --, y `R102`:
     * se prueban todas las listas, no solo la primera, porque la del array no
     * sirve. */
    const std::string offset =
        fmt("@overlay struct P {\n"
            "Section Sections[num_sections_del_fichero] @offset(e_lfanew + 24 "
            "+ opt_size) stride(40);\n"
            "}\n");
    check(offset.find("@offset(\n") != std::string::npos,
          "el parentesis de la anotacion se reparte");
    check(offset.find(") stride(40);") != std::string::npos,
          "y lo que sigue al cierre se queda con el");

    /* El `@` de una ANOTACION no se confunde con el de un desplazamiento: aquel
     * abre la linea y este va detras de un tipo y un nombre. */
    const std::string anotacion = fmt("class C {\n"
                                      "@Override\n"
                                      "public i32 f() { return 0; }\n"
                                      "}\n");
    check(anotacion.find("@Override") != std::string::npos,
          "una anotacion se queda como esta");
}

/**
 * @brief Casos escritos a mano, para lo que el corpus no cubre.
 */
void check_handwritten() {
    // `R11`: los CRLF se normalizan.
    const vx::fmt::FormatResult crlf =
        vx::fmt::format("i32 main() {\r\n\treturn 0;\r\n}\r\n", "<crlf>");
    check(crlf.text.find('\r') == std::string::npos,
          "los retornos de carro se van");

    // `R9`: sin espacio en blanco al final de la linea.
    const vx::fmt::FormatResult cola =
        vx::fmt::format("i32 main() {   \n\treturn 0;\t\n}\n", "<cola>");
    check(cola.text.find(" \n") == std::string::npos &&
              cola.text.find("\t\n") == std::string::npos,
          "no queda blanco al final de ninguna linea");

    // `R10`: el fichero acaba en UN salto de linea.
    const vx::fmt::FormatResult fin =
        vx::fmt::format("i32 main() { }\n\n\n\n", "<fin>");
    check(fin.text.size() >= 2 && fin.text.back() == '\n' &&
              fin.text[fin.text.size() - 2] != '\n',
          "el fichero acaba en un unico salto");

    // Un fuente vacio no revienta ni inventa contenido.
    const vx::fmt::FormatResult vacio = vx::fmt::format("", "<vacio>");
    check(vacio.ok && vacio.text.empty(), "un fuente vacio se queda vacio");

    // Un comentario suelto sobrevive: es lo que el lexer tira y aqui no.
    const std::string con_comentario = "// hola\ni32 main() { }\n";
    const vx::fmt::FormatResult com =
        vx::fmt::format(con_comentario, "<comentario>");
    check(com.text.find("// hola") != std::string::npos,
          "un comentario no se pierde");
}

} // namespace

/**
 * @brief La forma canonica de los numeros (`R106`-`R109`).
 *
 * Es la unica parte del formateador que reescribe el TEXTO de un token, asi
 * que conviene fijar caso por caso que reescribe y que no.  Lo que NO toca
 * importa tanto como lo que toca: un cero de mas en un decimal cambiaria como
 * se lee el numero, y reagrupar un `0xDEAD_BEEF` borraria los campos que su
 * autor marco.
 */
void check_numbers() {
    /* El literal va como ARGUMENTO y no como valor de una declaracion, para
     * que aqui se vea solo la forma canonica: en una declaracion `R108` le
     * pondria ademas el sufijo del tipo, y eso se comprueba aparte. */
    const auto one = [](const std::string &lit) {
        const std::string src = "i32 main() { g(" + lit + "); }\n";
        const std::string out = vx::fmt::format(src, "<num>").text;
        const size_t a = out.find("g(");
        if (a == std::string::npos) return std::string{};
        const size_t b = out.find(')', a);
        return out.substr(a + 2, b - a - 2);
    };

    // `R106` + `R107`: mayusculas y relleno hasta la anchura de un tipo.
    check(one("0xf") == "0x0F", "un hex de un digito se rellena a un byte");
    check(one("0xff") == "0xFF", "los digitos hex van en mayuscula");
    check(one("0xfff") == "0x0FFF", "tres digitos suben a cuatro (u16)");
    check(one("0xABCDEF") == "0x00ABCDEF",
          "seis digitos no son un tipo: suben a ocho (u32)");
    check(one("0x1234567890ABCDEF") == "0x1234567890ABCDEF",
          "dieciseis digitos ya son u64: se quedan");
    check(one("0b101") == "0b0101", "el binario se agrupa de cuatro en cuatro");
    check(one("0o7") == "0o007", "el octal, de tres en tres");

    // `R107`: un `_` ya puesto marca campos de un formato y no se reagrupa.
    check(one("0xDEAD_BEEF") == "0xDEAD_BEEF",
          "un hex ya agrupado por el autor no se toca");

    // `R109`: los millares de un decimal, a partir de cinco digitos.
    check(one("1000000") == "1_000_000", "un decimal largo agrupa millares");
    check(one("10000") == "10_000", "cinco digitos ya se agrupan");
    check(one("1000") == "1000", "cuatro se leen de un vistazo");
    check(one("2026") == "2026", "un ano se queda como esta");
    check(one("0.1234567") == "0.1234567",
          "detras del punto no hay millares que contar");

    // `R108`: el sufijo de tipo, separado.
    check(one("42i8") == "42_i8", "el sufijo se separa con guion bajo");
    check(one("0xFFu32") == "0xFF_u32", "tambien tras un hexadecimal");
    check(one("1e9i64") == "1e9_i64", "el `_` va tras el exponente, no dentro");

    // Idempotencia: pasar dos veces no puede seguir cambiando el numero.
    const char *twice[] = {"0x0F",  "0b0101",   "1_000_000",
                           "42_i8", "0xFF_u32", "0.1234567"};
    for (const char *lit : twice)
        check(one(lit) == lit, (std::string("ya canonico: ") + lit).c_str());
}

/**
 * @brief El argumento que se captura como TEXTO no se toca (`R110`).
 *
 * Aqui `P2` no basta: los tokens son los mismos y la diferencia solo se ve al
 * ejecutar el comptime, asi que el caso se comprueba mirando el texto.
 */
void check_raw_capture() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<raw>").text;
    };

    // Declarada en el propio fichero: se reconoce por su parametro `expr`.
    const std::string local = fmt("comptime string emit(expr code) {\n"
                                  "return code;\n"
                                  "}\n"
                                  "i32 main() {\n"
                                  "string s = emit( print(1); );\n"
                                  "return 0;\n"
                                  "}\n");
    check(local.find("emit( print(1); )") != std::string::npos,
          "los espacios dentro de una captura `expr` se conservan");

    // Sin declaracion a la vista, el `;` delata que dentro hay codigo y no una
    // expresion: ninguna expresion Vesta lleva uno.
    const std::string bysemi = fmt("i32 main() {\n"
                                   "string s = source( p++; );\n"
                                   "return 0;\n"
                                   "}\n");
    check(bysemi.find("source( p++; )") != std::string::npos,
          "un `;` entre parentesis marca el argumento como texto");

    // Y una llamada corriente se sigue formateando como siempre.
    const std::string plain = fmt("i32 main() {\n"
                                  "i32 v = suma( 1,2 );\n"
                                  "return 0;\n"
                                  "}\n");
    check(plain.find("suma(1, 2)") != std::string::npos,
          "una llamada normal no se confunde con una captura");
}

/**
 * @brief La columna del signo (`R111`).
 *
 * Un `-` corre su numero una columna respecto a los de al lado, y entonces las
 * cifras dejan de poder compararse de un vistazo, que es para lo que estan en
 * columna.
 */
void check_sign_column() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<signo>").text;
    };

    const std::string mixto = fmt("i32 f() {\n"
                                  "i8 minimo = -128;\n"
                                  "i8 maximo = 127;\n"
                                  "}\n");
    check(mixto.find("minimo = -128_i8;") != std::string::npos,
          "el valor con signo se queda donde estaba");
    check(mixto.find("maximo =  127_i8;") != std::string::npos,
          "el que no lo lleva reserva su columna");

    // `+` cuenta igual que `-`: los dos ocupan una columna.
    const std::string mas = fmt("i32 f() {\n"
                                "i64 a = +600;\n"
                                "i64 b = 40;\n"
                                "}\n");
    check(mas.find("b =  40_i64;") != std::string::npos,
          "un `+` tambien abre la columna del signo");

    // Sin ningun signo no hay nada que reservar.
    const std::string sin = fmt("i32 f() {\n"
                                "i64 a = 1;\n"
                                "i64 b = 40;\n"
                                "}\n");
    check(sin.find("a = 1_i64;") != std::string::npos,
          "sin signos los valores no se mueven");

    // Una llamada tambien recibe la columna: lo que devuelve se puede negar
    // igual, y `-suma(1, 2)` correria la linea entera.
    const std::string call = fmt("i32 f() {\n"
                                 "i64 a = -1;\n"
                                 "i64 b = 40;\n"
                                 "i64 c = suma(1, 2);\n"
                                 "}\n");
    check(call.find("b =  40_i64;") != std::string::npos,
          "una llamada en medio no bloquea la columna del signo");
    check(call.find("c =  suma(1, 2);") != std::string::npos,
          "y la llamada tambien la recibe");

    // Y la lleva la que de verdad va negada.
    const std::string negcall = fmt("i32 f() {\n"
                                    "i64 a = -suma(1, 2);\n"
                                    "i64 b = suma(3, 4);\n"
                                    "}\n");
    check(negcall.find("a = -suma(1, 2);") != std::string::npos &&
              negcall.find("b =  suma(3, 4);") != std::string::npos,
          "una llamada negada abre la columna para las demas");
}

/**
 * @brief Contratos: el `:` de una etiqueta y el reparto (`R112`).
 *
 * Una anotacion de contrato es una lista de DATOS, no de sentencias, y se
 * reparte como un parrafo: llenando lineas y alineando la continuacion con el
 * primer argumento.
 */
void check_contracts() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<contrato>").text;
    };

    // El `:` de una etiqueta va pegado al nombre, como en un mapa.
    const std::string etiquetas =
        fmt("@alloc(partial: 0, total: 0)\ni32 f() { return 0; }\n");
    check(etiquetas.find("@alloc(partial: 0, total: 0)") != std::string::npos,
          "el `:` de una etiqueta va pegado a su nombre");

    // El segundo `:` de un argumento pertenece al VALOR y va pegado por los
    // dos lados: `arch:arm64` es un solo atomo.
    const std::string atomo =
        fmt("@stack(0, when: arch:x86_64)\ni32 f() { return 0; }\n");
    check(atomo.find("when: arch:x86_64") != std::string::npos,
          "un atomo `clave:valor` no se separa");

    // Cada anotacion en su linea, aunque vinieran pegadas.
    const std::string sueltas =
        fmt("@nothrow @nopanic\ni32 f() { return 0; }\n");
    check(sueltas.find("@nothrow\n@nopanic") != std::string::npos,
          "los contratos se colocan uno por linea");

    /* Y una que no cabe se reparte uno por linea, con los VALORES en columna:
     * un contrato repartido es una tabla de dos columnas y se lee como tal. */
    const std::string largo =
        fmt("@complexity(partial_pre: O(1), partial_post: O(1), total_pre: "
            "O(n), total_post: O(n))\ni32 f() { return 0; }\n");
    check(largo.find("@complexity(\n") != std::string::npos,
          "una anotacion larga se parte tras su apertura");
    check(largo.find("partial_pre:  O(1),") != std::string::npos &&
              largo.find("partial_post: O(1),") != std::string::npos,
          "y los valores quedan en columna");
    check(largo.find("\n)") != std::string::npos,
          "el cierre vuelve a la altura de quien abrio");
}

/**
 * @brief El lote de espaciado: `R27`, `R44`, `R53`, `R54`, y el ultimo de una
 *        lista.
 *
 * Casos que el formateador hacia mal o no hacia, cada uno con el caso vecino
 * que NO debe cambiar: lo que distingue a los dos es justo lo que se estaba
 * decidiendo mal.
 */
void check_spacing_lote() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<lote>").text;
    };

    /* `R27`: el asterisco va pegado al TIPO, tambien en un parametro.  Antes
     * salia de tres formas segun donde estuviera: `i64 *datos` en un
     * parametro, `i64* local` en un local y `i64* * doble` en un doble. */
    const std::string ptr = fmt("i64 leer(i64* datos, i64 n) {\n"
                                "i64* local = datos;\n"
                                "i64** doble = &local;\n"
                                "return *local;\n"
                                "}\n");
    check(ptr.find("i64 leer(i64* datos") != std::string::npos,
          "en un parametro el `*` se pega al tipo");
    check(ptr.find("i64** doble") != std::string::npos,
          "y dos punteros seguidos no se separan");
    check(ptr.find("= &local;") != std::string::npos,
          "el `&` de direccion conserva su espacio tras el `=`");
    check(ptr.find("return *local;") != std::string::npos,
          "y un deref sigue pegado a lo que desreferencia");

    // Lo que NO debe cambiar: en una llamada, `a * b` es un producto.
    const std::string mul = fmt("i32 f() {\n i32 v = g(a * b, c);\n}\n");
    check(mul.find("g(a * b, c)") != std::string::npos,
          "un producto dentro de una llamada no se toca");

    // `R44`: un cuerpo vacio lleva un espacio; una lista vacia, no.
    check(fmt("i32 f() {}\n").find("i32 f() { }") != std::string::npos,
          "un cuerpo vacio se escribe `{ }`");
    check(fmt("i32 f() {\ni32 v[2] = {};\n}\n").find("= {};") !=
              std::string::npos,
          "pero una lista de inicializacion vacia se queda `{}`");

    // `R54`: el `;` de la cabecera de un `for` lleva espacio detras.
    const std::string bucle =
        fmt("i32 f() {\nfor (i32 i = 0;i < n;i = i + 1) {\ng();\n}\n}\n");
    check(bucle.find("for (i32 i = 0_i32; i < n; i = i + 1)") !=
              std::string::npos,
          "el `;` del `for` lleva espacio detras");
    check(fmt("i32 f() {\nfor (;;) {\ng();\n}\n}\n").find("for (;;)") !=
              std::string::npos,
          "y un `for` infinito no gana espacios de la nada");

    // `R53`: los cierres que continuan van pegados a la llave.
    const std::string enc =
        fmt("i32 f() {\nif (a) {\nb();\n}\nelse {\nc();\n}\n"
            "do {\ng();\n}\nwhile (h);\n}\n");
    check(enc.find("} else {") != std::string::npos,
          "el `else` se pega a la llave que cierra");
    check(enc.find("} while (h);") != std::string::npos,
          "y el `while` de un `do` tambien");

    /* Pero un `while` corriente NO: ahi empieza una sentencia nueva.  Los dos
     * se escriben igual, y solo se distinguen por quien abrio el bloque. */
    const std::string wh =
        fmt("i32 f() {\nif (a) {\nb();\n}\nwhile (c) {\nd();\n}\n}\n");
    check(wh.find("}\n\twhile (c)") != std::string::npos,
          "un `while` que no cierra un `do` no se junta");

    /* Y tampoco si el `}` lleva detras un comentario de linea: juntarlos
     * meteria el `else` DENTRO del comentario. */
    const std::string com =
        fmt("i32 f() {\nif (a) { b(); } // por que\nelse { c(); }\n}\n");
    check(com.find("// por que\n") != std::string::npos &&
              com.find("else") > com.find("// por que"),
          "un comentario detras de la llave impide juntar");

    /* El ULTIMO elemento de una lista tambien se alinea, aunque no lleve coma
     * (`R13` no la admite).  Antes se quedaba fuera de la columna de sus
     * hermanos -- y era el que mas cantaba, por cerrar el bloque. */
    const std::string en = fmt("enum E {\nA = 1,\nBB = 2,\nCCC = 3\n}\n");
    check(en.find("A   = 1,") != std::string::npos &&
              en.find("CCC = 3") != std::string::npos,
          "el ultimo valor de un enum comparte columna con los demas");
}

/**
 * @brief Una cosa por linea: `R26`, `R37`, `R43` y `R48`.
 *
 * Dos sentencias en la misma linea esconden la segunda, porque el ojo lee una
 * linea como una cosa.  Cada caso viene con su vecino que NO debe partirse:
 * lo que los separa es justo lo que se estaba decidiendo.
 */
void check_una_por_linea() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<lineas>").text;
    };

    // `R26`: una declaracion por linea.
    check(fmt("i32 f() {\ni32 a = 1; i32 b = 2;\n}\n")
                  .find("a = 1_i32;\n\ti32 b") != std::string::npos,
          "dos sentencias en una linea se separan");

    // `R43`: y un miembro de clase por linea.
    check(fmt("class C {\ni32 a; i32 b;\n}\n").find("i32 a;\n\ti32 b;") !=
              std::string::npos,
          "dos miembros en una linea se separan");

    /* Pero el `;` de la cabecera de un `for` NO cierra sentencia: los de en
     * medio van dentro de parentesis y el ultimo lo delata su cierre. */
    check(fmt("i32 f() {\nfor (i32 i = 0; i < n; i = i + 1) {\ng();\n}\n}\n")
                  .find("for (i32 i = 0_i32; i < n; i = i + 1)") !=
              std::string::npos,
          "la cabecera de un `for` no se parte");
    check(fmt("i32 f() {\nfor (;;) {\ng();\n}\n}\n").find("for (;;)") !=
              std::string::npos,
          "ni la de un `for` infinito");

    // `R37`: el variadico va pegado al tipo, como el `*` de un puntero.
    check(fmt("i32 f(i64 ... xs) { return 0; }\n").find("i64... xs") !=
              std::string::npos,
          "el variadico se pega al tipo");

    // `R48`: cada valor de un `enum` en su linea, con o sin carga.
    const std::string adt = fmt("enum M { Some(i64), None }\n");
    check(adt.find("enum M {\n\tSome(i64),\n\tNone\n}") != std::string::npos,
          "un enum con carga se reparte entero");
    const std::string simple = fmt("enum E { A = 1, B = 2 }\n");
    check(simple.find("\tA = 1,\n\tB = 2\n}") != std::string::npos,
          "y uno simple tambien, que es lo que `R47` da por hecho");
    check(fmt("enum V { }\n").find("enum V { }") != std::string::npos,
          "pero uno vacio se queda en su linea");

    /* La coma de DENTRO de una carga no separa valores: pertenece a la carga
     * y no puede partir la linea. */
    check(fmt("enum P { Par(i64, i64), Nada }\n").find("Par(i64, i64),") !=
              std::string::npos,
          "la coma de dentro de una carga no parte");
}

/**
 * @brief Un cuerpo de una sentencia sin llaves (`R6`, `R6b`).
 *
 * `R6` deja escribirlo sin llaves solo si cabe en la MISMA linea, y el motivo
 * es el `goto fail` de Apple: partido en dos, la indentacion puede mentir
 * sobre lo que hay dentro.  `R6b` es la otra direccion, la que hace que haya
 * una sola forma: uno que venga partido y quepa junto, se junta.
 */
void check_cuerpo_suelto() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<cuerpo>").text;
    };

    // Cabe: se junta.
    check(fmt("i32 f() {\nif (n < 2)\nreturn n;\n}\n")
                  .find("if (n < 2) return n;") != std::string::npos,
          "un cuerpo que cabe se junta con su cabecera");
    check(fmt("i32 f() {\nfor (i64 i = 0; i < n; i = i + 1)\ntotal += i;\n}\n")
                  .find("i = i + 1) total += i;") != std::string::npos,
          "tambien el de un `for`");

    /* No cabe: recibe LLAVES (`R6`).  Al nivel de su `if` se leeria como la
     * sentencia siguiente, y ese es el enganio del `goto fail`: con la llave
     * puesta, ese fallo no se puede escribir.
     *
     * Anadirlas cambia la lista de tokens, asi que el formateador lo DECLARA y
     * la comprobacion de `P2` exige que la unica diferencia sea esa. */
    const std::string largo =
        fmt("i32 f() {\nif (usuario.tiene_permiso() && !usuario.bloqueado() && "
            "x > 0)\nconceder(usuario, recurso, nivel, extra);\n}\n");
    check(largo.find("x > 0) {\n\t\tconceder(") != std::string::npos,
          "un cuerpo que no cabe recibe su llave de apertura");
    check(largo.find("extra);\n\t}") != std::string::npos,
          "y la de cierre, a la altura de la cabecera");
    check(largo.find("\t}\n}") != std::string::npos,
          "y el bloque queda cerrado dentro del de la funcion");

    // Un cuerpo con llaves no se toca, aunque quepa.
    check(fmt("i32 f() {\nif (a) {\ng();\n}\n}\n").find("if (a) {\n\t\tg();") !=
              std::string::npos,
          "un bloque con llaves no se junta");
}

/**
 * @brief Comentarios de bloque (`R21`, `R21b`).
 *
 * Los dos casos se distinguen por una sola cosa: si las lineas de
 * continuacion empiezan por `*`.  Con ellas, esa columna es una FORMA que hay
 * que mantener cuadrada; sin ellas, el texto es del autor y se copia tal cual.
 */
void check_comentarios_bloque() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<coment>").text;
    };

    // `R21`: los asteriscos caen bajo el del `/ *` que abre.
    const std::string doc =
        fmt("i32 f() {\n/**\n* hola\n* que tal\n*/\nreturn 0;\n}\n");
    check(doc.find("\t/**\n\t * hola\n\t * que tal\n\t */") !=
              std::string::npos,
          "los asteriscos de un comentario de bloque se alinean");

    /* `R21b`: sin ese patron no se toca.  Un dibujo, una tabla o un trozo de
     * otro lenguaje pegado ahi dentro se estropearia al reindentarlo. */
    const std::string arte =
        fmt("i32 f() {\n/*\n   +---+\n   | X |\n   +---+\n*/\nreturn 0;\n}\n");
    check(arte.find("   +---+\n   | X |\n   +---+") != std::string::npos,
          "un comentario que no sigue el patron se queda intacto");

    // Uno de una sola linea no tiene continuacion que alinear.
    check(fmt("i32 f() {\n/* corto */\nreturn 0;\n}\n").find("/* corto */") !=
              std::string::npos,
          "uno de una linea se queda como esta");
}

/**
 * @brief Cadenas de llamadas (`R94`, `R95`, `R96`).
 *
 * La excepcion a `R15`, puesta mirando a UFCS: cuando `f(x, y)` se pueda
 * escribir `x.f(y)`, encadenar sera la forma normal de trabajar sobre un
 * valor, y un formateador que no sepa repartirlas se queda corto justo donde
 * mas se usan.
 */
void check_cadenas() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<cadena>").text;
    };

    // No cabe: el receptor arriba y un eslabon por linea, con el punto delante.
    const std::string larga =
        fmt("i32 f() {\ni64 total = xs.filter(es_valido).map(a_precio)"
            ".descartar(cero).ordenar(criterio).sum();\n}\n");
    check(larga.find("= xs\n\t\t.filter(es_valido)") != std::string::npos,
          "el receptor se queda arriba y los eslabones bajan sangrados");
    check(larga.find("\n\t\t.sum();") != std::string::npos,
          "`R95`: se reparten TODOS, no unos si y otros no");

    // Cabe: se queda en una linea.
    check(fmt("i32 f() {\ni64 t = xs.filter(f).sum();\n}\n")
                  .find("xs.filter(f).sum();") != std::string::npos,
          "una cadena que cabe no se reparte");

    /* `R96`: con un solo eslabon no hay cadena, y lo que se reparte son sus
     * ARGUMENTOS. */
    const std::string uno =
        fmt("i32 f() {\ni64 v = objeto.metodo_con_un_nombre_larguisimo("
            "alfa, beta, gamma, delta, eps);\n}\n");
    check(uno.find(".metodo_con_un_nombre_larguisimo(\n") != std::string::npos,
          "un solo eslabon reparte sus argumentos, no la cadena");

    /* Una linea con LLAVES no es una expresion: lleva sentencias, y el punto
     * que se vea pertenece a una de ellas.  Salio en el corpus, con varios
     * `else if` en una linea. */
    const std::string mixta =
        fmt("i32 f() {\nif (a) { sb.uno(); } else if (b) { sb.dos(); }\n}\n");
    check(mixta.find("sb.uno();") != std::string::npos,
          "una linea con llaves no se trata como cadena");
}

/**
 * @brief Las reglas que cambian TOKENS (`R6`, `R29`, `R42`, `R74`).
 *
 * `P2` compara la lista de tokens, asi que estas cuatro estaban prohibidas
 * aunque ninguna cambie el programa -- se comprobo ejecutando las dos formas.
 * La salida fue verificar por INTENCION: el formateador declara lo que hace y
 * la comprobacion exige que la diferencia sea exactamente esa.
 *
 * Lo que de verdad hay que probar aqui no es que las apliquen, sino que la
 * salvaguarda SIGUE cazando lo que nadie declaro.
 */
void check_reglas_de_token() {
    const auto fmt = [](const std::string &s) {
        return vx::fmt::format(s, "<token>").text;
    };

    // `R74`: una anotacion sin argumentos pierde sus parentesis vacios.
    check(fmt("@Inline()\ni32 f() { return 0; }\n").find("@Inline\n") !=
              std::string::npos,
          "`@X()` se queda en `@X`");

    // `R29`: dos `>` que cierran genericos anidados se funden.
    check(
        fmt("i32 f() {\nCaja<Caja<i64> > c;\n}\n").find("Caja<Caja<i64>> c;") !=
            std::string::npos,
        "dos `>` de cierre pasan a ser `>>`");
    // Pero una comparacion NO: ahi son dos operadores distintos.
    check(fmt("i32 f() {\nbool v = (a > b) > c;\n}\n").find("(a > b) > c") !=
              std::string::npos,
          "una comparacion no se funde");

    // `R42`: los modificadores, en orden -- acceso, `static`, `final`.
    check(fmt("class C {\nstatic public i32 f() { return 0; }\n}\n")
                  .find("public static i32 f()") != std::string::npos,
          "los modificadores se ordenan");

    /* `R6`: un cuerpo que no cabe en la linea de su cabecera recibe llaves.
     * Sin ellas la indentacion puede mentir sobre lo que hay dentro, que es el
     * fallo de TLS de Apple de 2014. */
    const std::string largo =
        fmt("i32 f() {\nif (usuario.tiene_permiso() && !usuario.bloqueado() && "
            "x > 0)\nconceder(usuario, recurso, nivel, extra);\n}\n");
    check(largo.find("x > 0) {") != std::string::npos,
          "el cuerpo que no cabe recibe su llave");
    // Y el que SI cabe se queda sin ellas: `R6` permite esa forma.
    check(fmt("i32 f() {\nif (n < 2)\nreturn n;\n}\n")
                  .find("if (n < 2) return n;") != std::string::npos,
          "el que cabe se junta y no las lleva");

    /* LA COMPROBACION QUE IMPORTA: una diferencia que nadie declaro sigue
     * siendo un fallo.  Se simula pasando una reescritura vacia y comparando
     * dos textos que difieren de verdad. */
    check(!vx::fmt::same_program("i32 f() { return 1; }\n",
                                 "i32 f() { return 2; }\n"),
          "un cambio real se sigue detectando");
    check(!vx::fmt::same_program("i32 f() { g(); }\n", "i32 f() { }\n"),
          "y una llamada que desaparece, tambien");
    /* Ni siquiera declarando una reescritura de otra clase: la comprobacion
     * exige que lo que ve encaje con lo que esa reescritura produce. */
    std::vector<vx::fmt::Rewrite> falsa = {
        {vx::fmt::RewriteKind::DropEmptyParens, 3}};
    check(!vx::fmt::same_program("i32 f() { return 1; }\n",
                                 "i32 f() { return 2; }\n", falsa),
          "una reescritura declarada no tapa un cambio que no es el suyo");
}

/**
 * @brief Punto de entrada.
 * @param argc Numero de argumentos.
 * @param argv El primero opcional es la raiz del repositorio.
 * @return 0 si todo pasa.
 */
int main(int argc, char **argv) {
    std::printf("=== fmt_test ===\n");
    const std::string root = (argc > 1) ? argv[1] : ".";

    check_handwritten();
    check_unicode_width();
    check_spacing();
    check_colon_uses();
    check_alignment();
    check_field_shapes();
    check_numbers();
    check_raw_capture();
    check_sign_column();
    check_contracts();
    check_spacing_lote();
    check_una_por_linea();
    check_cuerpo_suelto();
    check_comentarios_bloque();
    check_cadenas();
    check_reglas_de_token();

    /* La lista de ficheros se genera fuera: no hay glob portable en C++17 sin
     * <filesystem>, que en este arbol ha dado guerra con mas de un toolchain.
     */
    std::string list;
    if (!read_file(root + "/tests/vx/fmt_corpus.txt", list)) {
        std::printf("  no se encontro tests/vx/fmt_corpus.txt\n");
        std::printf("  generala con:  python tests/vx/fmt_corpus.py\n");
        return 2;
    }
    std::istringstream lines(list);
    std::string path;
    int files = 0;
    while (std::getline(lines, path)) {
        while (!path.empty() && (path.back() == '\r' || path.back() == '\n'))
            path.pop_back();
        if (path.empty() || path[0] == '#') continue;
        check_file(root + "/" + path);
        ++files;
    }

    std::printf("=== fmt_test: %d checks OK, %d fallidos  (%d ficheros) ===\n",
                g_passed, g_failed, files);
    return g_failed == 0 ? 0 : 1;
}
