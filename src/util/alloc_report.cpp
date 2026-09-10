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
 * @file util/alloc_report.cpp
 * @brief De donde salen las reservas que no dicen para que son, CON NOMBRE.
 *
 * EL REPARTO DE TRABAJO, que es lo unico que hay que entender aqui: el
 * asignador MIDE y el compilador LEE.  `vesta_alloc` es una libreria aparte que
 * se distribuye sola, asi que no sabe -- ni debe saber -- leer tablas de
 * simbolos; lo unico que puede dar es la direccion desde la que se reservo.
 * Este proyecto si sabe, porque su enlazador lee ese mismo formato con cada
 * objeto que enlaza, y por eso los nombres se ponen aqui.
 *
 * SIN NOMBRES, LAS DIRECCIONES.  Un binario despojado no tiene tabla de
 * simbolos, y ahi la respuesta correcta es el desplazamiento y decir que no hay
 * nombres -- no una columna en blanco, que se lee como "este sitio no reserva"
 * cuando lo que pasa es que no se sabe como se llama.
 */

#include "util/alloc_report.h"

#include "util/report/alloc_csv.h" // el mismo informe como DATO, para una herramienta
#include "util/report/alloc_sites.h"
#include "util/env_flags.h"
#include "util/alloc/host_allocator.h" // el total sin declarar, para dar contexto
#include "util/symbols/module_symbols.h" // de QUIEN es una direccion, antes de nombrarla
#include "util/os/os_memory.h"
#include "util/symbols/self_dwarf.h" // la cadena de inline: quien LLAMO, no quien reserva
#include "util/symbols/self_symbols.h"
#include "util/mem/vesta_memcpy.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

/* La pregunta correcta NO es que COMPILADOR es, sino que ABI de C++ hay debajo.
 * `<cxxabi.h>` es la de Itanium, la que traen libstdc++ y libc++; con la STL de
 * MSVC no existe -- alli los nombres se manglan de otra forma y se desharian
 * con `UnDecorateSymbolName` de dbghelp.  Preguntando por el compilador, clang
 * con el ABI de MSVC entraba aqui (define `__clang__`) y no encontraba la
 * cabecera. */
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER)
#include <cxxabi.h>
#define VESTA_HAS_ITANIUM_DEMANGLE 1
#endif

/* Solo para saber el ancho de la consola, y solo si la salida ES una consola.
 * Ver `console_width`. */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace util {

namespace {

/**
 * @brief El nombre de C++ tal como se escribio, a partir del manglado.
 *
 * Si no se puede, se devuelve el manglado TAL CUAL: es feo pero es cierto, y
 * ademas se puede pasar a `c++filt`.  Devolver una cadena vacia perderia el
 * unico dato que habia.
 */
std::string demangle(const char *mangled) {
#if defined(VESTA_HAS_ITANIUM_DEMANGLE)
    int status = 0;
    /* Reserva con `malloc` por contrato de la ABI y se suelta con `free`.  Es
     * el unico sitio de todo esto donde se reserva, y corre al final, una vez
     * por linea del informe. */
    char *out = abi::__cxa_demangle(mangled, nullptr, nullptr, &status);
    if (status == 0 && out != nullptr) {
        std::string s(out);
        std::free(out);
        return s;
    }
    if (out != nullptr) std::free(out);
#endif
    return std::string(mangled);
}

/// Un desplazamiento desde la base del modulo, como se escribe en el informe.
/// Cabe de sobra en el buffer: son 16 digitos como mucho.
std::string hex_offset(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof(b), "+0x%llx", (unsigned long long)v);
    return std::string(b);
}

/// Cambia TODAS las apariciones.  `std::string` no lo trae hecho.
void replace_all(std::string &s, const char *from, const char *to) {
    const size_t n = std::strlen(from);
    const size_t m = std::strlen(to);
    for (size_t i = s.find(from); i != std::string::npos; i = s.find(from, i + m))
        s.replace(i, n, to);
}

/**
 * @brief Si en @p i empieza un argumento de plantilla que nadie escribe.
 *
 * Son los que el lenguaje pone POR DEFECTO.  Nadie teclea
 * `std::vector<T, std::allocator<T>>`: escribe `std::vector<T>`, y las dos
 * cosas son el mismo tipo.  Ensenar la forma larga no anade un dato, esconde
 * el que hay -- que es `T` -- detras de tres veces su longitud.
 */
bool is_default_arg(const std::string &s, size_t i) {
    /* Los de siempre, mas las POLITICAS con las que libstdc++ arma sus
     * contenedores por dentro.  `std::_Hashtable` lleva cinco -- como extraer
     * la clave, como repartir el hash, cuando reorganizar... -- y son las
     * mismas para cualquier `unordered_map`: no dicen nada de ESTA reserva y
     * ocupan mas que los tipos que si lo dicen.
     *
     * Unos llevan argumentos de plantilla y otros no, asi que no vale con
     * buscar el `<`: hay que aceptar tambien que detras venga el final del
     * argumento. */
    static const char *const kDefaults[] = {
        "std::allocator",           "std::char_traits",
        "std::less",                "std::hash",
        "std::equal_to",            "std::_Select1st",
        "std::_Identity",           "std::_Mod_range_hashing",
        "std::_Default_ranged_hash", "std::_Prime_rehash_policy",
        "std::_Hashtable_traits",   "std::__uniq_ptr_impl",
    };
    for (const char *d : kDefaults) {
        const size_t n = std::strlen(d);
        if (s.compare(i, n, d) != 0) continue;
        /* Que el nombre acabe AHI y no sea el principio de otro: `std::hash`
         * no puede tragarse un `std::hasher_propio`. */
        const char c = (i + n < s.size()) ? s[i + n] : '\0';
        if (c == '<' || c == ',' || c == '>' || c == ' ' || c == '\0')
            return true;
    }
    return false;
}

/**
 * @brief Si en @p i empieza la POLITICA DE CERROJO de los punteros contados.
 *
 * `(__gnu_cxx::_Lock_policy)2` sale en cada pieza de un `shared_ptr` -- el
 * bloque de cuentas, el contador, el propio puntero -- y siempre vale lo mismo.
 * Nadie la escribe.
 *
 * Va en su PROPIA comprobacion, y no en la lista de arriba, porque esta si se
 * puede quitar cuando es el PRIMER argumento: nunca es la carga de nada.  Las
 * otras no -- `std::allocator_traits<std::allocator<T>>` lleva un
 * `std::allocator` de primero y ahi es el dato, no un valor por defecto --, y
 * quitarlo dejaria `std::allocator_traits` a secas, que es otra cosa.
 */
bool is_lock_policy(const std::string &s, size_t i) {
    static const char kPolicy[] = "(__gnu_cxx::_Lock_policy)";
    return s.compare(i, sizeof(kPolicy) - 1, kPolicy) == 0;
}

/**
 * @brief Quita esos argumentos, con la coma que los precede.
 *
 * Cuenta `<` y `>` para saber donde acaba la parte de plantilla: recortar por
 * texto partiria los anidados.
 *
 * Y DESPUES SIGUE HASTA EL FINAL DEL ARGUMENTO, que es lo que faltaba.  Un
 * argumento no acaba en el `>`: puede seguir con ` const&`, `*` o `::algo`, y
 * al borrar solo hasta el cierre esa cola se quedaba huerfana y se pegaba al
 * argumento anterior.  Salia texto que no existe en ningun sitio -- se vio un
 * `std::_Default_ranged_hash const& const&` en el informe --, o sea que la
 * simplificacion estaba INVENTANDO, que es peor que no simplificar.
 */
std::string drop_default_args(const std::string &in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size();) {
        /* Detras de una coma se quita cualquiera de los valores por defecto;
         * detras del `<` que abre la lista, SOLO la politica de cerrojo, por lo
         * que explica `is_lock_policy`. */
        const bool opens = in[i] == '<';
        if (in[i] == ',' || opens) {
            size_t j = i + 1;
            while (j < in.size() && in[j] == ' ') ++j;
            const bool policy = is_lock_policy(in, j);
            /* Tras el `<` SOLO la politica; tras una coma, cualquiera. */
            if (policy || (!opens && is_default_arg(in, j))) {
                size_t k = j;
                if (policy) {
                    /* `(__gnu_cxx::_Lock_policy)2`: lleva parentesis DENTRO,
                     * asi que el barrido normal se paraba en su `)` y dejaba el
                     * numero suelto.  Se salta el molde y luego las cifras. */
                    k = j + std::strlen("(__gnu_cxx::_Lock_policy)");
                    while (k < in.size() && in[k] >= '0' && in[k] <= '9') ++k;
                } else {
                    int depth = 0;
                    for (; k < in.size(); ++k) {
                        if (in[k] == '<') {
                            ++depth;
                        } else if (in[k] == '>') {
                            if (depth == 0) break; // cierra la lista de fuera
                            if (--depth == 0) {
                                ++k;
                                break;
                            }
                        } else if (depth == 0 &&
                                   (in[k] == ',' || in[k] == ')')) {
                            break; // el argumento no tenia plantilla
                        }
                    }
                }
                /* La COLA del argumento: `const`, `&`, `*`, `::`...  Se para en
                 * lo que separa un argumento del siguiente, o en un `<` que
                 * abriria otro tipo. */
                while (k < in.size() && in[k] != ',' && in[k] != '>' &&
                       in[k] != ')' && in[k] != '<')
                    ++k;
                if (opens) {
                    /* El `<` se queda -- abre la lista --, y si detras venia
                     * otro argumento se come su coma para no dejar `<, X>`. */
                    out.push_back('<');
                    if (k < in.size() && in[k] == ',') {
                        ++k;
                        while (k < in.size() && in[k] == ' ') ++k;
                    }
                }
                i = k; // se van el separador y el argumento ENTERO
                continue;
            }
        }
        out.push_back(in[i]);
        ++i;
    }
    /* Una lista que se queda VACIA no se escribe: `std::__shared_count<>` no
     * existe en ningun sitio, y ese es el caso cuando la politica de cerrojo
     * era el unico argumento. */
    replace_all(out, "<>", "");
    return out;
}

/**
 * @brief Todos los tipos con plantilla que aparecen en @p s, sin repetir.
 *
 * Un tipo es un nombre cualificado seguido de una lista `<...>` equilibrada.  Se
 * busca desde cada `<` hacia atras para coger el nombre, y hacia delante hasta
 * su cierre; asi salen tambien los anidados, que es lo que hace falta para
 * poder abreviar primero el de fuera.
 */
std::vector<std::string> template_types(const std::string &s) {
    std::vector<std::string> out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '<') continue;
        int depth = 0;
        size_t close = std::string::npos;
        for (size_t j = i; j < s.size(); ++j) {
            if (s[j] == '<') {
                ++depth;
            } else if (s[j] == '>' && --depth == 0) {
                close = j;
                break;
            }
        }
        if (close == std::string::npos) continue;
        size_t start = i;
        while (start > 0) {
            const char c = s[start - 1];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == ':')
                --start;
            else
                break;
        }
        if (start == i) continue; // un `<` sin nombre delante
        std::string t = s.substr(start, close - start + 1);
        bool dup = false;
        for (const std::string &o : out)
            if (o == t) dup = true;
        if (!dup) out.push_back(std::move(t));
    }
    std::sort(out.begin(), out.end(),
              [](const std::string &a, const std::string &b) {
                  return a.size() > b.size();
              });
    return out;
}

/// Cuantas veces aparece @p what dentro de @p s.
unsigned count_of(const std::string &s, const std::string &what) {
    unsigned n = 0;
    for (size_t i = s.find(what); i != std::string::npos;
         i = s.find(what, i + what.size()))
        ++n;
    return n;
}

/**
 * @brief Le pone NOMBRE a los tipos largos que se repiten dentro de un nombre.
 *
 * POR QUE.  En una sola linea del informe se llego a medir
 * `std::unordered_map<std::string, std::vector<Assembly::Bytecode::InstrInfo>>`
 * -- setenta y cuatro caracteres -- CUATRO veces, mas el par de la misma clave
 * y valor otras dos: cuatrocientos cuarenta de sus seiscientos ochenta
 * caracteres eran el mismo texto repetido.
 *
 * Y NO SE PIERDE NADA, que es la diferencia con recortar: la definicion va
 * debajo, en la misma linea logica, asi que el nombre sigue completo y sigue
 * siendo buscable.  Es lo que haria cualquiera explicandolo en un papel.
 *
 * Se hace de mayor a menor a proposito: abreviando primero el tipo de fuera
 * desaparecen con el los de dentro, y no salen dos definiciones para lo mismo.
 *
 * @param defs Recibe las definiciones, ya formateadas.
 */
std::string abbreviate_repeats(std::string s, std::vector<std::string> &defs) {
    defs.clear();
    /* Por debajo de esto no compensa: la definicion ocuparia mas que lo que
     * ahorra.  Y mas de cuatro convierte la linea en un criptograma. */
    constexpr size_t kMinLen = 40;
    constexpr unsigned kMaxAbbrev = 4;

    for (const std::string &t : template_types(s)) {
        if (defs.size() >= kMaxAbbrev) break;
        if (t.size() < kMinLen) break; // vienen ordenados: los demas son menores
        if (count_of(s, t) < 2) continue;
        char name[8];
        std::snprintf(name, sizeof(name), "T%u", unsigned(defs.size()) + 1);
        /* Que la abreviatura no exista ya en el texto, o al leerla se
         * confundiria con un tipo de verdad. */
        if (s.find(name) != std::string::npos) continue;
        replace_all(s, t.c_str(), name);
        defs.push_back(std::string(name) + " = " + t);
    }
    return s;
}

/**
 * @brief El ancho de la consola, o cero si la salida no es una consola.
 *
 * DOS DESTINOS, DOS FORMAS.  A una consola conviene partir las lineas largas,
 * porque si no se enrollan solas por donde caiga y se leen fatal.  A un fichero
 * o a una tuberia NO: ahi lo que se hace es `grep`, y una linea partida deja de
 * casar con lo que se busca -- que es precisamente para lo que se guarda el
 * informe --.
 *
 * Asi que se pregunta, en vez de elegir un ancho fijo que estaria mal en los
 * dos casos.
 */
unsigned console_width() {
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(h, &info)) {
        const int w = info.srWindow.Right - info.srWindow.Left + 1;
        if (w > 40) return unsigned(w);
    }
    return 0;
#else
    if (!isatty(STDERR_FILENO)) return 0;
    struct winsize ws;
    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 40)
        return unsigned(ws.ws_col);
    return 0;
#endif
}

/**
 * @brief Parte @p text para que quepa, con sangria colgante.
 * @param width  Cuanto cabe.  Cero deja el texto de una pieza.
 * @param indent Con cuantos espacios empiezan las lineas de continuacion.
 *
 * Se corta por donde se separan las cosas -- una coma de plantilla, un espacio
 * --, nunca a mitad de un identificador, para que el nombre siga siendo
 * buscable trozo a trozo.  Y si un trozo no cabe ni el solo, sale entero y se
 * enrolla: recortarlo seria perderlo.
 */
std::string wrap(const std::string &text, unsigned width, unsigned indent) {
    if (width == 0 || text.size() <= width) return text;
    std::string out;
    const std::string pad(indent, ' ');
    size_t line_start = 0;
    unsigned room = width;
    while (text.size() - line_start > room) {
        /* El ultimo sitio donde se puede partir dentro de lo que cabe. */
        size_t cut = std::string::npos;
        for (size_t i = line_start; i < line_start + room && i < text.size(); ++i)
            if (text[i] == ' ' || text[i] == ',') cut = i;
        if (cut == std::string::npos || cut <= line_start) break; // no se puede
        out.append(text, line_start, cut - line_start + 1);
        out.push_back('\n');
        out.append(pad);
        line_start = cut + 1;
        while (line_start < text.size() && text[line_start] == ' ') ++line_start;
        room = width > indent ? width - indent : width;
    }
    out.append(text, line_start, std::string::npos);
    return out;
}

/**
 * @brief Los argumentos de la lista de plantilla que abre en @p open.
 * @param close Recibe el indice del `>` que la cierra.
 * @return false si no cierra, y entonces no se toca nada: el nombre se queda
 *         como estaba, que es preferible a reescribirlo a medias.
 */
bool template_args(const std::string &s, size_t open,
                   std::vector<std::string> &out, size_t &close) {
    out.clear();
    int depth = 0;
    size_t start = open + 1;
    for (size_t i = open; i < s.size(); ++i) {
        if (s[i] == '<') {
            ++depth;
        } else if (s[i] == '>') {
            if (--depth == 0) {
                out.push_back(s.substr(start, i - start));
                close = i;
                return true;
            }
        } else if (s[i] == ',' && depth == 1) {
            out.push_back(s.substr(start, i - start));
            start = i + 1;
            while (start < s.size() && s[start] == ' ') ++start;
        }
    }
    return false;
}

/**
 * @brief Llama a los contenedores por el nombre con el que se escribieron.
 *
 * POR QUE.  Un `unordered_map` no existe dentro de libstdc++: lo que hay es un
 * `std::_Hashtable` con la clave, el par y cinco politicas.  El informe
 * ensenaba eso, que es cierto y no se parece a nada de lo que hay en el codigo.
 * Y es reconocible sin ambiguedad: si el segundo argumento es
 * `std::pair<CLAVE const, VALOR>`, eso es un mapa de CLAVE a VALOR y no puede
 * ser otra cosa.
 *
 * NO se pierde nada.  `std::unordered_map<K, V>` nombra exactamente la misma
 * instanciacion que el `_Hashtable` largo -- las politicas son las que el
 * lenguaje pone solo, igual que `std::allocator` --, y ademas es lo que se
 * puede buscar en el codigo, que es para lo que sirve la columna.
 */
std::string rewrite_containers(std::string s) {
    struct Shape {
        const char *inner; ///< como lo llama libstdc++
        const char *map;   ///< si el segundo argumento es un par
        const char *set;   ///< si el segundo argumento es la propia clave
    };
    /* Las CLASES BASE con las que libstdc++ arma el contenedor, y que llevan
     * EXACTAMENTE los mismos argumentos que el: la clave, el valor y las
     * politicas.  `_Insert_base<K, pair<K const,V>, ...>::insert` es
     * `unordered_map<K,V>::insert`, que es lo que dice el codigo -- ahi no hay
     * ninguna `_Insert_base` escrita --.
     *
     * Se pueden meter todas en la misma tabla precisamente porque comparten la
     * lista de argumentos; una con otra disposicion leeria la clave donde esta
     * el valor, que es el fallo que ya costo el `_Hash_node`. */
    static const Shape kShapes[] = {
        {"std::_Hashtable<", "std::unordered_map", "std::unordered_set"},
        {"std::_Insert_base<", "std::unordered_map", "std::unordered_set"},
        {"std::_Map_base<", "std::unordered_map", "std::unordered_set"},
        {"std::_Hashtable_base<", "std::unordered_map", "std::unordered_set"},
        {"std::_Rehash_base<", "std::unordered_map", "std::unordered_set"},
        {"std::_Equality<", "std::unordered_map", "std::unordered_set"},
        {"std::_Rb_tree<", "std::map", "std::set"},
    };

    /* Los NODOS y los ITERADORES, que salen tanto como el contenedor: reservar
     * en un mapa es construir un nodo, e insertar devuelve un iterador, asi que
     * aparecen en media cadena de inline.  Van aparte porque su forma es OTRA
     * -- el par es el PRIMER argumento, no el segundo --, y meterlos en la
     * tabla de arriba habria leido la clave donde esta el valor. */
    struct Inner {
        const char *name;    ///< como lo llama libstdc++
        const char *as_map;  ///< si dentro hay un par, de que mapa es
        const char *as_set;  ///< y si no, de que conjunto
        const char *what;    ///< que pieza suya
    };
    static const Inner kInner[] = {
        {"std::_Hash_node<", "std::unordered_map", "std::unordered_set",
         "::node"},
        {"std::_Node_iterator<", "std::unordered_map", "std::unordered_set",
         "::iterator"},
        {"std::_Node_const_iterator<", "std::unordered_map",
         "std::unordered_set", "::const_iterator"},
        {"std::_Rb_tree_node<", "std::map", "std::set", "::node"},
        {"std::_Rb_tree_iterator<", "std::map", "std::set", "::iterator"},
        {"std::_Rb_tree_const_iterator<", "std::map", "std::set",
         "::const_iterator"},
    };
    for (const Inner &in : kInner) {
        for (size_t at = s.find(in.name); at != std::string::npos;
             at = s.find(in.name, at + 1)) {
            const size_t open = at + std::strlen(in.name) - 1;
            std::vector<std::string> args;
            size_t close = 0;
            if (!template_args(s, open, args, close)) break;
            if (args.empty()) continue;
            const std::string &val = args[0];
            /* CON par dentro es de un mapa; SIN el, de un conjunto -- que
             * guarda el elemento pelado --.  Los de conjunto se dejaban antes
             * sin tocar y son la mayoria: `std::_Hash_node<std::string, true>`
             * salia seiscientas veces en un solo informe. */
            std::string cont;
            if (val.compare(0, 10, "std::pair<") == 0) {
                const size_t sep = val.find(" const, ");
                if (sep == std::string::npos || val.back() != '>') continue;
                cont = std::string(in.as_map) + "<" + val.substr(10, sep - 10) +
                       ", " + val.substr(sep + 8, val.size() - sep - 9) + ">";
            } else {
                cont = std::string(in.as_set) + "<" + val + ">";
            }
            s = s.substr(0, at) + cont + in.what + s.substr(close + 1);
            at = 0;
        }
    }

    /* EL ITERADOR DE UN VECTOR O DE UNA CADENA.  Dentro de libstdc++ es
     * `__gnu_cxx::__normal_iterator<T*, C>`: un puntero envuelto para que no se
     * mezcle con otro contenedor del mismo tipo.  En el codigo se escribe
     * `C::iterator`, que es lo mismo y la mitad de largo, y la constancia se
     * lee del puntero -- `T const*` es el constante --.
     *
     * Salia trescientas catorce veces en un informe. */
    {
        static const char kIt[] = "__gnu_cxx::__normal_iterator<";
        for (size_t at = s.find(kIt); at != std::string::npos;
             at = s.find(kIt, at + 1)) {
            const size_t open = at + sizeof(kIt) - 2;
            std::vector<std::string> args;
            size_t close = 0;
            if (!template_args(s, open, args, close)) break;
            if (args.size() < 2 || args[0].empty() || args[0].back() != '*')
                continue;
            /* `T const*` es un iterador constante; `T*`, uno normal. */
            const bool is_const =
                args[0].size() > 7 &&
                args[0].compare(args[0].size() - 7, 7, " const*") == 0;
            s = s.substr(0, at) + args[1] +
                (is_const ? "::const_iterator" : "::iterator") +
                s.substr(close + 1);
            at = 0;
        }
    }

    /* `__gnu_cxx::new_allocator<T>` es la clase BASE de `std::allocator<T>`, y
     * solo aparece porque es donde libstdc++ pone el `operator new`.  En el
     * codigo se escribe la derivada, y ademas asi las dos formas que salen en
     * la misma linea dejan de parecer cosas distintas. */
    replace_all(s, "__gnu_cxx::new_allocator<", "std::allocator<");
    /* Lo mismo con el puntero contado: `__shared_ptr` es la base de
     * `shared_ptr` y `__shared_count` su contador. */
    replace_all(s, "std::__shared_ptr<", "std::shared_ptr<");
    /* Y las bases que guardan el almacenamiento de los contenedores de sitio
     * contiguo: `_Vector_base<T>::_M_allocate` es donde reserva un
     * `vector<T>`, y llamarla por la derivada es como se lee en el codigo. */
    replace_all(s, "std::_Vector_base<", "std::vector<");
    replace_all(s, "std::_Deque_base<", "std::deque<");

    for (const Shape &sh : kShapes) {
        for (size_t at = s.find(sh.inner); at != std::string::npos;
             at = s.find(sh.inner, at + 1)) {
            const size_t open = at + std::strlen(sh.inner) - 1;
            std::vector<std::string> args;
            size_t close = 0;
            if (!template_args(s, open, args, close)) break;
            if (args.size() < 2) continue;

            const std::string &key = args[0];
            const std::string &second = args[1];
            std::string nuevo;
            if (second == key) {
                nuevo = std::string(sh.set) + "<" + key + ">";
            } else {
                /* `std::pair<CLAVE const, VALOR>`: se comprueba que la clave
                 * sea LA MISMA, porque si no esto no es un mapa de esa clave y
                 * reescribirlo seria inventarse el tipo. */
                const std::string pref = "std::pair<" + key + " const, ";
                if (second.compare(0, pref.size(), pref) != 0) continue;
                if (second.empty() || second.back() != '>') continue;
                const std::string val =
                    second.substr(pref.size(), second.size() - pref.size() - 1);
                nuevo = std::string(sh.map) + "<" + key + ", " + val + ">";
            }
            s = s.substr(0, at) + nuevo + s.substr(close + 1);
            at = 0; // el texto cambio de sitio; se vuelve a buscar desde el
        }
    }
    return s;
}

/**
 * @brief El nombre como se escribio, no como lo guarda el enlazador.
 *
 * POR QUE.  Un manglado desmanglado es tecnicamente la respuesta y
 * practicamente ninguna: cuatrocientos caracteres de los que trescientos son
 * argumentos por defecto y una firma que aqui no distingue nada.  Quien lee
 * este informe quiere saber si es un vector o una cadena y de que, y eso estaba
 * ahi dentro sin poder verse.
 *
 * Y NO SE RECORTA NADA, por largo que salga.  Todo lo que se quita aqui es un
 * valor POR DEFECTO -- el mismo tipo escrito largo, que el lenguaje repone
 * solo --, asi que el nombre que sale sigue nombrando exactamente lo mismo y
 * se puede buscar en el codigo, pegar en `c++filt` o meter en un `grep`.  Un
 * nombre con puntos suspensivos en medio no sirve para ninguna de las tres:
 * poner `...` ahorra ancho a cambio de lo unico para lo que existe la columna.
 */
std::string readable(const char *mangled) {
    std::string s = demangle(mangled);

    /* Detalles de como esta HECHA la libreria, no del tipo.  `__cxx11` es el
     * marcador de la ABI nueva de las cadenas y `__detail` es donde libstdc++
     * esconde lo suyo; en el codigo no se escribe ni uno ni otro. */
    replace_all(s, "std::__cxx11::", "std::");
    replace_all(s, "std::__detail::", "std::");
    replace_all(s, "[abi:cxx11]", "");

    s = drop_default_args(s);

    /* El desmanglador deja un espacio antes de cada cierre -- `vector<T >` --
     * porque antes de C++11 pegar dos era un desplazamiento.  Hoy se escriben
     * juntos, y quitarlo AQUI es ademas lo que permite reconocer la cadena
     * abajo: al quitarle los argumentos por defecto queda `basic_string<char >`
     * y con el espacio dentro no casaria.  En bucle porque un cierre pegado
     * destapa el siguiente. */
    for (size_t before = 0; before != s.size();) {
        before = s.size();
        replace_all(s, " >", ">");
    }

    /* Y ya sin `char_traits` ni `allocator` dentro, la cadena se puede llamar
     * por su nombre. */
    replace_all(s, "std::basic_string<char>", "std::string");
    replace_all(s, "std::basic_string<wchar_t>", "std::wstring");

    /* Y por ultimo, los contenedores por su nombre de verdad.  Va AL FINAL
     * porque necesita que las politicas ya no esten: es reconocer
     * `_Hashtable<K, pair<K const, V>>`, y con las cinco politicas en medio el
     * segundo argumento no seria el par. */
    s = rewrite_containers(s);
    return s;
}

/// El trozo de @p s que va entre @p from y el siguiente separador.  Vacio si no
/// hay nada.  Los separadores son los dos, porque en las rutas que guarda el
/// compilador se mezclan segun quien las escribiera.
std::string segment_after(const std::string &s, const char *from) {
    const size_t at = s.find(from);
    if (at == std::string::npos) return std::string();
    const size_t start = at + std::strlen(from);
    size_t end = start;
    while (end < s.size() && s[end] != '/' && s[end] != '\\') ++end;
    return s.substr(start, end - start);
}

/**
 * @brief El informe se arma en memoria y se escribe DE UNA VEZ.
 *
 * POR QUE.  `stderr` no tiene bufer -- el estandar lo exige, para que un
 * mensaje de error salga aunque el proceso muera justo detras --, asi que cada
 * `fprintf` es una escritura al sistema.  Con una linea por sitio eso daba
 * igual; con la cadena de funciones inlineadas debajo de cada uno son varios
 * miles de lineas, y en Windows cada escritura a consola es cara de verdad.
 *
 * Armarlo en una cadena y soltarlo con un `fwrite` cambia miles de llamadas al
 * sistema por una.  Y no se pierde la propiedad que hace a `stderr` util aqui:
 * esto corre al final, cuando ya no queda nada que pueda reventar en medio, y
 * se vacia antes de volver.
 *
 * NO se usa `setvbuf` sobre `stderr`, que seria mas corto: solo esta definido
 * antes de la primera operacion sobre el flujo, y aqui ya se ha escrito mucho.
 */
struct Sink {
    std::string buf;

    /**
     * @brief Cuanto se acumula antes de soltarlo.
     *
     * NO se guarda el informe entero para escribirlo al final, aunque seria
     * mas rapido.  Esto corre al morir el proceso, y si algo revienta a mitad
     * -- el propio asignador que se esta midiendo, por ejemplo -- todo lo que
     * hubiera en el bufer se va con el: se pierde precisamente el informe que
     * explicaba que estaba pasando.  Ya paso mientras se escribia esto.
     *
     * Con sesenta y cuatro KiB quedan unas pocas escrituras en vez de miles, y
     * lo que se puede perder es lo ultimo, no todo.
     */
    static constexpr size_t kMax = 64 * 1024;

    /// Anade texto formateado.  Mide primero y reserva lo justo, para que un
    /// nombre de C++ con plantillas -- que pasa de largo cualquier tamano fijo
    /// -- no se recorte en silencio.
    void add(const char *fmt, ...) __attribute__((format(printf, 2, 3))) {
        va_list a1, a2;
        va_start(a1, fmt);
        va_copy(a2, a1);
        const int n = std::vsnprintf(nullptr, 0, fmt, a1);
        va_end(a1);
        if (n > 0) {
            const size_t was = buf.size();
            buf.resize(was + size_t(n) + 1);
            std::vsnprintf(&buf[was], size_t(n) + 1, fmt, a2);
            buf.resize(was + size_t(n)); // fuera el terminador
        }
        va_end(a2);
        if (buf.size() >= kMax) flush();
    }

    void flush() {
        if (buf.empty()) return;
        std::fwrite(buf.data(), 1, buf.size(), stderr);
        std::fflush(stderr);
        buf.clear();
    }
};

/// Parte una ruta en carpeta y nombre.  La carpeta se queda con la barra final
/// para que al pegarla otra vez salga la ruta exacta que habia.
void split_path(const char *path, std::string &dir, std::string &base) {
    dir.clear();
    base.clear();
    if (path == nullptr) return;
    const std::string p(path);
    const size_t slash = p.find_last_of("/\\");
    if (slash == std::string::npos) {
        base = p;
        return;
    }
    dir = p.substr(0, slash + 1);
    base = p.substr(slash + 1);
}

/// El ultimo directorio ANTES de @p marker.  Para cuando lo que sigue al marco
/// es un fichero y no un modulo: ahi lo que agrupa es el componente que lo
/// contiene.  Vacio si no se puede sacar.
std::string component_before(const std::string &s, const char *marker) {
    const size_t at = s.find(marker);
    if (at == std::string::npos || at == 0) return std::string();
    size_t start = at;
    while (start > 0 && s[start - 1] != '/' && s[start - 1] != '\\') --start;
    return s.substr(start, at - start);
}

/**
 * @brief De QUE es este codigo: de la libreria estandar, del arranque, de una
 *        libreria de terceros o de que modulo nuestro.
 *
 * PARA QUE.  Porque "quien reserva" tiene dos respuestas utiles y muy
 * distintas.  Una es la funcion exacta, que ya sale.  La otra es de quien es el
 * codigo -- si el grueso se lo lleva la libreria estandar, una libreria que
 * viene de fuera o un modulo nuestro --, y esa es la que dice donde mirar
 * primero.  Con cuatrocientas filas de `std::` mezcladas con las propias, esa
 * respuesta no se ve.
 *
 * La RUTA del fichero es la senal buena, y viene de la informacion de
 * depuracion.  Sin ella se cae al nombre de la funcion, que distingue lo de
 * `std::` y poco mas -- y eso se dice, en vez de repartir a ojo.
 */
std::string module_of(const char *file, const char *fn) {
    if (file != nullptr) {
        const std::string p(file);
        /* La libreria estandar vive dentro del directorio del compilador, y eso
         * es mas fiable que el nombre: hay plantillas suyas instanciadas con
         * tipos nuestros y al reves.
         *
         * Los tres sitios donde aparece, que no son el mismo segun quien
         * compile: `include/c++/<version>` en GCC (y en MinGW con barra
         * invertida), y `include/c++/v1` en la libreria de Clang.  Buscar solo
         * la de MinGW dejaria sin clasificar TODA la libreria estandar en
         * Linux, y eso no falla: sale como "sin clasificar", que se lee como si
         * no se supiera de donde viene. */
        if (p.find("include/c++") != std::string::npos ||
            p.find("include\\c++") != std::string::npos)
            return p.find("/v1/") != std::string::npos ? "libc++" : "libstdc++";
        /* El arranque y la libreria de C del sistema, en sus dos sabores. */
        if (p.find("mingw-w64") != std::string::npos ||
            p.find("crossdev") != std::string::npos ||
            p.find("/sysdeps/") != std::string::npos ||
            p.find("/glibc") != std::string::npos ||
            p.find("/csu/") != std::string::npos)
            return "CRT del sistema";
        /* Las que vienen de fuera se agrupan por su nombre, que es el
         * directorio que las contiene. */
        const std::string vendor = segment_after(p, "libs/SourceCode/");
        if (!vendor.empty()) return vendor;
        /* Y lo nuestro, POR MODULO: el directorio que sigue a `src/` o a
         * `include/` es el subsistema (runtime, ir, aot, vx, util...), que es
         * la agrupacion que de verdad se usa para decidir.
         *
         * Salvo cuando ahi hay un FICHERO y no un directorio, que pasa con los
         * componentes cuyos fuentes cuelgan directos de `src/`.  Entonces el
         * modulo es el componente que contiene ese `src/`, no el fichero:
         * agrupar por fichero daria una fila por cada uno y ninguna sumaria
         * nada. */
        const std::string mine = segment_after(p, "/src/");
        if (!mine.empty())
            return mine.find('.') == std::string::npos
                       ? mine
                       : component_before(p, "/src/");
        const std::string inc = segment_after(p, "/include/");
        if (!inc.empty())
            return inc.find('.') == std::string::npos
                       ? inc
                       : component_before(p, "/include/");
        const std::string tst = segment_after(p, "/tests/");
        if (!tst.empty()) return "tests/" + tst;
    }
    /* Sin ruta queda el nombre, que solo separa lo evidente.  Y se marca como
     * lo que es -- una suposicion por el nombre -- para que no se lea igual que
     * lo que salio de la informacion de depuracion. */
    if (fn != nullptr) {
        const std::string s(fn);
        if (s.compare(0, 5, "std::") == 0 || s.compare(0, 11, "__gnu_cxx::") == 0 ||
            s.compare(0, 4, "_ZSt") == 0 || s.compare(0, 4, "_ZNS") == 0)
            return "libstdc++?";
    }
    return "sin clasificar";
}

/// Lo que se lleva cada modulo.  Una lista corta con busqueda lineal: son unas
/// decenas de grupos y se recorre una vez, al final.
struct ModuleTotal {
    std::string name;
    uint64_t allocs = 0;
    uint64_t bytes = 0;
};

void add_to_module(std::vector<ModuleTotal> &tot, const std::string &name,
                   uint64_t allocs, uint64_t bytes) {
    for (ModuleTotal &m : tot)
        if (m.name == name) {
            m.allocs += allocs;
            m.bytes += bytes;
            return;
        }
    tot.push_back(ModuleTotal{name, allocs, bytes});
}

/**
 * @brief El modulo de un marco, en almacenamiento que sobrevive a la llamada.
 *
 * POR QUE UNA REJILLA FIJA Y NO UNA CADENA.  Porque el exportador lee estos
 * punteros DESPUES de que el gancho vuelva -- resuelve la cadena entera y luego
 * escribe las filas --, asi que devolver el `c_str()` de un temporal daria un
 * puntero a memoria ya liberada.  Y sin destructor a proposito: esto corre
 * desde un manejador de salida, y un estatico ya destruido en ese momento es
 * exactamente el fallo que costo una tarde con el almacen de nombres.
 *
 * Una ranura por PROFUNDIDAD, no una por sitio: solo tienen que sobrevivir los
 * marcos del sitio que se esta escribiendo.
 */
const char *module_text(unsigned depth, const char *file, const char *fn) {
    static char pool[64][64];
    if (depth >= 64) return nullptr;
    const std::string name = module_of(file, fn);
    /* Acotado en el sitio de la copia, que es lo que le falta al compilador
     * para no avisar: sabe que `pool[depth]` mide 64 y no puede saber cuanto
     * mide `name` sin esto. */
    const size_t room = sizeof(pool[0]) - 1;
    const size_t n = name.size() < room ? name.size() : room;
    vesta_memcpy(pool[depth], name.c_str(), n);
    pool[depth][n] = '\0';
    return pool[depth];
}

/**
 * @brief Un marco para una direccion que NO es de nuestra imagen.
 *
 * De ella se pueden decir dos cosas ciertas -- de que modulo es y como se llama
 * el simbolo mas cercano dentro de el -- y una que no: fichero y linea, que
 * exigen la informacion de depuracion de un fichero ajeno y que en una maquina
 * normal ni siquiera esta instalada para el runtime de C.  Sale vacia, que se
 * lee como "no se", en vez de rellenarse con algo de aqui.
 *
 * El MODULO va con su ruta y no por `module_text`: ese reparte los ficheros
 * FUENTE entre las partes de este proyecto, y una direccion de `msvcrt.dll` no
 * pertenece a ninguna.  Decir de que biblioteca es ya es el dato.
 */
unsigned resolve_other_module(const void *pc, AllocFrame *out, unsigned max) {
    VestaModuleInfo m;
    if (max == 0 || !vesta_module_of(pc, &m)) return 0;

    out[0].file = nullptr;
    out[0].line = 0;
    out[0].inlined = false;
    out[0].module = m.path;

    if (m.symbol != nullptr) {
        out[0].function = m.symbol;
        return 1;
    }
    /* Sin simbolo -- un modulo despojado, o una direccion en codigo que no
     * exporta nada --, pero el DESPLAZAMIENTO sigue siendo un dato, y ademas es
     * el unico estable entre ejecuciones: la direccion se mueve con cada carga.
     * Misma forma que el respaldo del camino propio, para que quien lea el
     * informe vea UNA convencion y no dos. */
    static char foreign[64];
    std::snprintf(foreign, sizeof(foreign), "+0x%llx",
                  (unsigned long long)m.offset);
    out[0].function = foreign;
    return 1;
}

/// Cuantos bits puestos.  Sin `<bit>`, que es de C++20 y esto es C++17.
int popcount64(uint64_t v) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_popcountll(v);
#else
    int n = 0;
    while (v != 0) {
        v &= v - 1;
        ++n;
    }
    return n;
#endif
}

} // namespace

/* La version publica.  Se saca del anonimo porque el informe de CAIDAS necesita
 * lo mismo: un nombre decorado en una traza de pila es ilegible, y ahi dentro
 * van los tipos de los argumentos.  Escribirlo dos veces seria tener dos ideas
 * de que es un nombre legible, y la segunda se quedaria vieja sin que nadie lo
 * notara. */
std::string readable_symbol(const char *mangled) {
    return readable(mangled);
}

/**
 * @brief El gancho de nombres que el asignador no puede tener todavia.
 *
 * `vesta_alloc` mide y se distribuye sola, asi que no lee tablas de simbolos ni
 * debe.  Este proyecto SI: su enlazador lee ese mismo formato con cada objeto.
 * Por eso la resolucion entra por aqui.
 *
 * Es temporal por diseno.  Cuando la lectura de simbolos se mude al asignador,
 * lo unico que cambia es quien rellena este gancho; las columnas del CSV y la
 * herramienta que las lee se quedan igual.
 */
unsigned resolve_frames(const void *pc, AllocFrame *out, unsigned max) {
    /* Aqui se devuelve el nombre CRUDO, tal cual lo dice la informacion de
     * depuracion.  Ponerlo legible es otra cosa y va por otro gancho
     * (`alloc_set_name_formatter`), porque no es la misma pregunta: esta es
     * "de quien es esta direccion" y aquella es "como se escribe eso en MI
     * lenguaje" -- y la segunda la contesta cada proyecto, que un binario de
     * Vesta no mangla como C++. */

    /* DE QUIEN ES, ANTES DE NADA.  Los tres intentos de abajo leen la imagen
     * PROPIA -- su informacion de depuracion, su tabla de simbolos, su
     * `.pdata` --, y ninguno comprobaba que la direccion lo fuera.  Mientras
     * todas las reservas venian del programa daba igual; desde que el
     * asignador sirve tambien al runtime de C por dentro, hay direcciones que
     * son de `msvcrt.dll` o de `libc.so` por construccion, y ahi los tres
     * fallan y el sitio se queda sin nombre.
     *
     * La misma pregunta se hace en `vesta_self_resolver`, dentro del
     * asignador.  Estan las dos porque este resolutor anade lo que aquel no
     * puede saber -- a que MODULO logico del proyecto pertenece un fichero --,
     * pero la parte de "esta direccion no es mia" es identica, y por eso las
     * dos se apoyan en la misma funcion en vez de tener cada una su criterio. */
    if (!vesta_module_is_self(pc)) return resolve_other_module(pc, out, max);

    SelfFrame frames[64];
    const unsigned n =
        self_inline_frames(pc, frames, max < 64 ? max : 64);
    if (n > 0) {
        const unsigned got = n < max ? n : max;
        for (unsigned i = 0; i < got; ++i) {
            out[i].function = frames[i].function;
            out[i].file = frames[i].file;
            out[i].line = frames[i].line;
            out[i].inlined = frames[i].inlined;
            out[i].module = module_text(i, frames[i].file,
                                        frames[i].function);
        }
        return got;
    }
    /* Sin informacion de depuracion queda la tabla de simbolos, que da UN
     * marco y sin fichero.  Es menos, pero es lo que hay, y devolver cero
     * dejaria el arbol sin raiz teniendo un nombre a mano. */
    size_t off = 0;
    if (const char *name = self_symbol(pc, &off)) {
        out[0].function = name;
        out[0].file = nullptr;
        out[0].line = 0;
        out[0].inlined = false;
        /* Sin ruta, `module_of` solo separa lo evidente por el nombre -- y lo
         * marca como suposicion.  Que devuelva poco no es razon para no
         * preguntar: agrupar la libreria estandar ya es la mitad del reparto. */
        out[0].module = module_text(0, nullptr, name);
        return 1;
    }

    /* Y SIN NOMBRES TAMPOCO SE DEVUELVE NADA VACIO.
     *
     * En una construccion despojada -- Release -- no hay simbolos ni
     * informacion de depuracion, pero `.pdata` sigue ahi: es una SECCION, no
     * una tabla de simbolos, asi que `--strip-all` no se la lleva.  De ella
     * sale donde empieza la funcion que contiene la direccion, y con eso el
     * arbol agrupa todos los sitios de una misma funcion bajo el mismo nodo en
     * vez de dejar cada uno suelto.
     *
     * No es un nombre, y no se disfraza de uno: sale como el desplazamiento que
     * es.  Pero un `fn +0x10c1760` con seis sitios debajo dice mucho mas que
     * seis direcciones sin relacion aparente. */
    static char fallback[64];
    const void *fn = nullptr;
    if (self_function_range(pc, &fn, nullptr)) {
        std::snprintf(fallback, sizeof(fallback), "fn +0x%llx",
                      (unsigned long long)(uintptr_t(fn) -
                                           uintptr_t(os_module_base())));
        out[0].function = fallback;
        out[0].file = nullptr;
        out[0].line = 0;
        out[0].inlined = false;
        /* Aqui no hay ni nombre ni ruta, asi que no hay nada que clasificar.
         * Sale vacio, que se lee como "no se sabe" -- y no como un modulo. */
        out[0].module = nullptr;
        return 1;
    }
    return 0;
}

/**
 * @brief Como se escribe un nombre de C++ para que lo lea una persona.
 *
 * Es lo que este proyecto sabe hacer y el asignador no tiene por que saber: el
 * desmanglado y todo lo que acerca el nombre al codigo -- los contenedores por
 * su nombre, los valores por defecto fuera --.  Ver `readable`.
 *
 * El almacen es estatico y se reusa porque el contrato del gancho dice que lo
 * devuelto vale hasta la siguiente llamada: quien pregunta lo escribe antes de
 * volver a preguntar.  Guardar todos los nombres seria quedarse con miles de
 * cadenas para un informe que se escribe una vez.
 */
const char *format_name(const char *raw) {
    if (raw == nullptr) return nullptr;
    static std::string held;
    held = readable(raw);
    return held.c_str();
}

void report_alloc_sites() {
    if (!flag_on(FlagId::HostAllocSites)) return;

    /* Todo lo que sigue se acumula aqui y sale de una sola escritura.  Ver
     * `Sink`: con la cadena de inline debajo de cada sitio esto son miles de
     * lineas, y `stderr` escribe cada una al sistema por separado. */
    Sink out;

    /* La tabla de simbolos se construye AQUI, antes de la foto, y el orden no
     * es un detalle: construirla RESERVA -- ciento treinta y dos mil nombres
     * que se copian a una cadena que crece --, o sea que es un sitio mas.
     *
     * Con la foto tomada antes, esas reservas todavia no existian y el sitio se
     * quedaba fuera: el informe se dejaba fuera SU PROPIO coste.  Medido, no es
     * un detalle tampoco -- el sitio que mas reservaba de todo el proceso,
     * 95.675 reservas y el 90% del total, no salia en esta lista y solo
     * aparecia en el volcado crudo del asignador, sin nombre y al final, donde
     * parecia de otro --.  Un informe que se excluye a si mismo miente
     * justamente sobre lo que mas reserva. */
    const size_t symbols = self_symbol_count();

    /* Y EL GANCHO DE NOMBRES SE ENCHUFA AQUI, no mas abajo junto al volcado a
     * ficheros.  Estaba dentro del `if` del CSV, y la consecuencia era que el
     * volcado de sitios del ASIGNADOR -- que corre despues de este informe,
     * desde su propia salida -- imprimia desplazamientos crudos mientras el CSV
     * del mismo proceso escribia `parse_tokens`.  La misma medida en dos
     * calidades, y la pobre es la que ve quien no sabe que existe el CSV.
     *
     * Enchufarlo aqui no cuesta nada de mas: la tabla de simbolos ya se acaba
     * de construir tres lineas arriba, que era lo unico caro. */
    alloc_set_symbol_resolver(&resolve_frames);
    alloc_set_name_formatter(&format_name);

    /* En la PILA y de tamano fijo: esto corre al final, cuando lo que interesa
     * es que salga el informe, no darle mas trabajo al asignador que se esta
     * midiendo.
     *
     * Y con sitio para TODOS.  Con 64 la foto salia llena en cualquier
     * compilacion de verdad, asi que la lista no era "los sitios", era "unos
     * cuantos" -- y encima los mas gordos, que son justo los que uno ya sabe --.
     * El tope de la tabla del asignador son `kMaxThreads * kSlots` entradas
     * distintas; esto coge cuatro mil, que sobra para lo que se mide (una
     * compilacion entera se queda en unos centenares) y ocupa un cuarto de mega
     * de pila, que en el hilo principal no es nada.  Si aun asi se llenara, se
     * DICE mas abajo en vez de cortar en silencio.
     *
     * Sigue en la pila y no en un estatico: un estatico serian esos 256 KiB en
     * el binario y en la memoria de CUALQUIER ejecucion, se pida el informe o
     * no, y aqui la pila no aprieta -- el hilo principal se enlaza con 128 MiB
     * y esto corre cuando ya no queda nada debajo --. */
    constexpr unsigned kMax = 4096;
    AllocSite sites[kMax];
    /* LAS TRES CIFRAS SE LEEN JUNTAS, Y ESE ES EL PUNTO.
     *
     * Antes se tomaba la foto aqui y el contador de reservas sesenta lineas mas
     * abajo, con la construccion de la tabla de simbolos por medio -- que
     * reserva a decenas de miles --.  Comparar dos cifras tomadas en momentos
     * distintos de un informe que reserva mientras se imprime daba un 224,5% de
     * "cobertura", o sea mas del cien por cien, y eso se leia como un fallo del
     * asignador cuando era un fallo de la MEDIDA.  Medido despues: sobre el
     * proceso entero las dos cuadran (176.051 entradas frente a 172.464
     * reservas), asi que lo unico que fallaba era el instante de la lectura. */
    const unsigned n = alloc_sites_snapshot(sites, kMax);
    const HostAllocStats st_at_snapshot = host_alloc_stats();
    const uint64_t entries_at_snapshot = host_new_calls();
    if (n == 0) {
        out.add(
                     "[reservas] no se apunto ningun sitio.  Con "
                     "VESTA_HOST_ALLOC_SITES=1 se apunta solo lo que llega SIN "
                     "declarar su proposito: si todo lo declara, esto es la "
                     "respuesta correcta.\n");
        out.flush();
        return;
    }

    const uintptr_t base = uintptr_t(os_module_base());
    out.add(
                 "[reservas] los %u sitios que reservan sin declarar su "
                 "proposito -- TODOS, de mayor a menor:\n",
                 n);
    /* Y si la foto se lleno, se dice.  Una lista cortada se lee como completa,
     * y aqui lo que se viene a buscar -- lo que falta por declarar -- es
     * justamente lo que se queda en la cola. */
    if (n == kMax)
        out.add(
                     "           OJO: cabian %u y se llenaron todos, asi que "
                     "puede haber mas sin ensenar.  Sube `kMax` en "
                     "`src/util/alloc_report.cpp`.\n",
                     kMax);
    /* Si no hay informacion de depuracion se DICE, en vez de no ensenar
     * cadenas de inline y dejar que se lea como "aqui no habia nada
     * inlineado" -- que con el optimizador encendido es siempre falso. */
    const size_t units = self_dwarf_units();
    if (units == 0)
        out.add(
                     "           SIN INFORMACION DE DEPURACION: no se puede "
                     "decir que funciones se inlinearon en cada sitio, que es "
                     "lo unico que dice quien LLAMO.  Se construye con "
                     "`-DCMAKE_BUILD_TYPE=Profile`.\n");
    else
        out.add(
                     /* `%llu` con conversion explicita, no `%zu`: el `printf`
                      * de msvcrt no conoce la `z`, asi que ahi salia la letra
                      * en vez del numero -- y el argumento se perdia.  Lo dijo
                      * el compilador; se ve en el informe solo si alguien mira
                      * esa linea. */
                     "           %llu unidades de compilacion con informacion "
                     "de depuracion; debajo de cada sitio, la cadena de "
                     "funciones inlineadas de dentro hacia fuera.\n",
                     (unsigned long long)units);
    if (symbols == 0)
        out.add(
                     "           SIN TABLA DE SIMBOLOS en este binario: salen "
                     "los desplazamientos desde la base del modulo (%p).  Se "
                     "resuelven con `addr2line -f -C -e <binario>` sobre una "
                     "construccion que los conserve.\n",
                     (const void *)base);

    /* La suma de lo que cada sitio SE GANO.  Con las cotas superiores esto
     * pasaba del 100% de las reservas reales -- se midio un 192,5% -- porque
     * una cuenta heredada se contaba tantas veces como entradas la arrastraran.
     * Restando lo heredado, la suma cabe en el total por construccion. */
    uint64_t total_allocs = 0, total_bytes = 0;
    for (unsigned i = 0; i < n; ++i) {
        total_allocs += sites[i].count - sites[i].over;
        total_bytes += sites[i].bytes - sites[i].over_bytes;
    }

    /* CONTRA QUE se compara: cuantas reservas pequenas hubo en todo el proceso.
     * Sin esta cifra, una lista que cubriera el 3% se leeria igual que una que
     * cubriera el 90%, y las dos se usarian para decidir.
     *
     * Y aparte, cuantas siguen SIN declarar proposito, que es la cifra que dice
     * cuanto queda por migrar. */
    /* La de la FOTO, no una tomada ahora: entre una y otra este mismo informe
     * ha reservado, y compararlas seria comparar dos instantes distintos.  Ver
     * la nota junto a la foto. */
    const HostAllocStats st = st_at_snapshot;
    const uint64_t total = st.small_allocs;
    /* Lo que se pidio apuntar y no cupo.  Con esto y la suma de la tabla ya se
     * puede decir de que lado esta un descuadre con las reservas contadas. */
    const uint64_t skipped = alloc_sites_skipped();
    const uint64_t untagged = st.by_tag[AllocTag{}.raw()];

    out.add( "  %12s %6s %10s %8s  %-15s %-8s  %s\n", "reservas",
                 "% ", "MiB", "media", "proposito", "forma", "sitio");

    /// Cuanto cabe de ancho.  Cero cuando la salida no es una consola, y
    /// entonces no se parte nada.
    const unsigned cols = console_width();

    std::vector<ModuleTotal> by_module;
    /// Las raices que se quitan de las cabeceras de grupo, para poder decirlas
    /// al final: una ruta acortada sin decir de donde cuelga no se puede abrir.
    std::vector<std::string> roots;
    for (unsigned i = 0; i < n; ++i) {
        size_t off = 0;
        const char *name = self_symbol(sites[i].pc, &off);
        /* Una cadena y no un buffer fijo: un nombre de C++ con plantillas pasa
         * de largo de cualquier tamano que se escriba aqui, y `snprintf`
         * recortaria lo que no cupiera SIN DECIRLO.  Es el mismo recorte
         * callado que se acaba de quitar de `readable`, escondido en el tipo
         * del destino.  Aqui se reserva, pero esto corre una vez por linea del
         * informe y al final de todo. */
        std::string where;

        /* EL TRAMO EXACTO de la funcion, que sale de `.pdata` en Windows y del
         * tamano del simbolo en Linux.  Va SIEMPRE, tenga nombre o no, y no
         * sustituye a nada: es informacion que antes no se daba. */
        const void *fn = nullptr;
        size_t fn_size = 0;
        const bool has_range = self_function_range(sites[i].pc, &fn, &fn_size);
        const size_t in_fn =
            has_range ? size_t(uintptr_t(sites[i].pc) - uintptr_t(fn)) : 0;

        /* El NOMBRE y el SITIO van aparte, y no pegados en una cadena.
         *
         * Con la cadena de inline debajo, el nombre ya sale ahi -- marcado como
         * `[la funcion real]` -- y repetirlo arriba es lo que hacia la fila
         * ilegible.  Pero cuando NO hay cadena, la fila es el unico sitio donde
         * aparece.  Juntandolos habia que decidir con un `find` sobre el texto,
         * y eso fallaba justo en las filas que no tienen tramo: unas salian
         * cortas y otras largas sin motivo aparente. */
        std::string fn_name;
        if (name != nullptr) {
            /* Desmanglado Y ADEMAS legible: ver `readable`.  Desmanglar solo
             * cambia un nombre ilegible por otro cuatro veces mas largo. */
            fn_name = readable(name);
            where = "+" + std::to_string(off);
            /* Y SE CONTRASTA.  Si el tramo NO empieza donde el simbolo, ese
             * simbolo no es la funcion que contiene la direccion: es el anterior
             * mas cercano, que es lo unico que la tabla de simbolos puede dar.
             * Pasa con las funciones que no dejan simbolo.  Antes se ensenaba el
             * nombre equivocado sin que nada lo delatara.
             *
             * El nombre NO se quita: sigue siendo el mejor dato que hay y con el
             * aviso al lado ya no engana. */
            if (has_range && uintptr_t(sites[i].pc) - off != uintptr_t(fn))
                where += " [OJO: nombre del simbolo ANTERIOR; la funcion que "
                         "contiene esta direccion empieza en " +
                         hex_offset(uintptr_t(fn) - base) + "]";
        } else {
            /* SIN NOMBRES -- una construccion despojada -- el tramo es lo unico
             * que hay, y es mas de lo que parece: dos sitios con la misma
             * funcion base son el mismo trozo de codigo, asi que las filas se
             * pueden juntar a ojo aunque ninguna tenga nombre. */
            where = hex_offset(uintptr_t(sites[i].pc) - base);
            if (has_range)
                where += " en la funcion " + hex_offset(uintptr_t(fn) - base);
        }

        if (has_range) {
            where += " (byte " + std::to_string(in_fn) + " de " +
                     std::to_string(fn_size) + ")";
        } else {
            /* Sin tramo no se puede contrastar, y eso se DICE: callarlo haria
             * pasar por comprobado lo que no lo esta.  Pasa donde no hay
             * registro de desenrollado -- una hoja, o codigo generado en
             * ejecucion -- y tambien en x86-32, donde `.pdata` no existe. */
            where += " (sin tramo con el que contrastar)";
        }

        /* LA FORMA, que es medio eje de la etiqueta (D9): en cuantas clases de
         * tamano cae este sitio.  Una sola = pide siempre lo mismo, o sea
         * `Fixed`.  Varias = esta creciendo, y eso es lo que NO puede ir a una
         * arena, porque al crecer abandona el buffer anterior. */
        const int clases = popcount64(sites[i].class_mask);
        char forma[16];
        if (sites[i].large == sites[i].count)
            std::snprintf(forma, sizeof(forma), "grande");
        else if (clases <= 1)
            std::snprintf(forma, sizeof(forma), "fija");
        else
            std::snprintf(forma, sizeof(forma), "crece/%d", clases);

        /* EL PROPOSITO CON EL QUE SE RESERVO, que es la columna que hace que
         * esto no sea el informe de un asignador cualquiera.  Al lado de la
         * forma MEDIDA: si un sitio se declara `fija` y aqui sale `crece/6`,
         * la declaracion esta mal -- y esa comparacion es todo el objetivo del
         * plan (la etiqueta se mide, no se declara). */
        const AllocTag tag = AllocTag::from_raw(sites[i].tag);
        /* LO QUE ESTE SITIO SE GANO, no la cota superior.  La tabla tiene sitio
         * acotado y al llenarse una ventana el que entra HEREDA la cuenta del
         * que echa; sin restar lo heredado, los sitios llegaban a sumar el
         * 192,5% de las reservas reales y veinte filas seguidas ensenaban la
         * misma cifra -- que era una sola cuenta copiandose hacia delante --.
         * Ver `AllocSite::over`. */
        const uint64_t hechas = sites[i].count - sites[i].over;
        const uint64_t bytes = sites[i].bytes - sites[i].over_bytes;

        /* SI DEBAJO VA LA CADENA, el nombre no se repite arriba.
         *
         * El ultimo marco de la cadena es esta misma funcion -- sale marcado
         * como `[la funcion real]` --, asi que ponerlo tambien en la fila era
         * escribir dos veces lo mismo, y es lo que hacia esta linea imposible de
         * leer.  No se pierde nada: esta ahi debajo, entero.
         *
         * Sin cadena -- una construccion sin informacion de depuracion -- la
         * fila es el UNICO sitio donde aparece, y ahi se queda como estaba. */
        SelfFrame frames[64];
        const unsigned nf = self_inline_frames(sites[i].pc, frames, 64);
        if (nf == 0 && !fn_name.empty()) where = fn_name + " " + where;

        out.add( "  %12llu %5.1f%% %10.1f %8llu  %-15s %-8s  %s\n",
                     (unsigned long long)hechas,
                     total == 0 ? 0.0
                                : 100.0 * double(hechas) / double(total),
                     double(bytes) / (1024.0 * 1024.0),
                     (unsigned long long)(hechas == 0 ? 0 : bytes / hechas),
                     tag.unknown() ? "SIN DECLARAR" : alloc_tag_name(tag), forma,
                     where.c_str());

        /* Y DEBAJO, LA CADENA DE INLINE ENTERA.
         *
         * El nombre de arriba es el de la funcion que existe en el binario, y
         * es cierto, pero con el optimizador encendido esa funcion se ha comido
         * a otras veinte y la que interesa casi nunca es la de fuera.  Medido
         * aqui mismo: un sitio salia como `std::pair<...>::pair` -- claro que
         * un `pair` reserva -- y tenia DIECIOCHO marcos inlineados, el ultimo
         * de los cuales era `include/emmit/parser_to_bytecode.h:103`.  Esa si
         * es la respuesta.
         *
         * Se ensenan TODOS y no solo el que cae en codigo nuestro: cual es el
         * interesante depende de lo que uno venga a mirar, y quedarse con uno
         * seria decidirlo aqui por quien lee.  Van de dentro hacia fuera, que
         * es como se leen. */

        /* DE QUIEN ES ESTE SITIO.  Se mira el marco de MAS AFUERA, que es la
         * funcion que existe de verdad en el binario: los de dentro son
         * plantillas de la libreria estandar instanciadas con tipos nuestros, y
         * atribuirle la reserva a ellas diria que casi todo es de `std::` --
         * cierto y sin ninguna utilidad, porque quien decidio reservar es el de
         * fuera. */
        add_to_module(by_module,
                      nf > 0 ? module_of(frames[nf - 1].file,
                                         frames[nf - 1].function)
                             : module_of(nullptr, name),
                      hechas, bytes);

        /* AGRUPADOS POR FICHERO, y la carpeta UNA sola vez.
         *
         * Sin esto cada marco repetia la ruta entera del compilador --
         * `C:/TDM-GCC-64/lib/gcc/x86_64-w64-mingw32/10.3.0/include/c++/bits/`,
         * noventa caracteres -- dieciocho veces seguidas, mas una sangria de
         * cincuenta y dos, y ninguna linea entraba en la pantalla.  Nada de eso
         * era informacion: era la MISMA informacion repetida.
         *
         * Se saca a una cabecera por carpeta, con de quien es el codigo al
         * lado, y cada marco se queda con lo suyo: el fichero, la linea y la
         * funcion entera, sin recortar.  La sangria dice que es una cadena; la
         * flecha sobraba. */
        std::string cur_dir;
        bool first = true;
        for (unsigned k = 0; k < nf; ++k) {
            std::string dir, base;
            split_path(frames[k].file, dir, base);
            if (first || dir != cur_dir) {
                cur_dir = dir;
                first = false;
                const std::string mod =
                    module_of(frames[k].file, frames[k].function);
                /* La cabecera ensena lo que DISTINGUE, no la raiz que ya dice
                 * el modulo: para la libreria estandar, medio centenar de
                 * caracteres de ruta del compilador son siempre los mismos y
                 * solo importa si es `bits/` o `ext/`.  La raiz entera sale una
                 * vez, arriba del informe. */
                std::string tail = dir;
                for (const char *marker : {"include/c++/", "include\\c++\\",
                                           "libs/SourceCode/"}) {
                    const size_t at = tail.find(marker);
                    if (at != std::string::npos) {
                        /* Lo que se quita se APUNTA, y sale al final del
                         * informe.  Acortar una ruta sin decir de donde cuelga
                         * la deja sin poder abrir, que es para lo que sirve. */
                        const std::string root =
                            dir.substr(0, at + std::strlen(marker));
                        bool seen = false;
                        for (const std::string &r : roots)
                            if (r == root) seen = true;
                        if (!seen) roots.push_back(root);
                        tail = tail.substr(at + std::strlen(marker));
                        break;
                    }
                }
                out.add("      %-16s %s\n", mod.c_str(),
                        dir.empty() ? "(sin fichero)"
                                    : (tail.empty() ? dir.c_str()
                                                    : tail.c_str()));
            }
            /* El sitio dentro del fichero primero y alineado, que es por donde
             * se busca; el nombre detras, que es lo que se lee. */
            char place[64];
            if (base.empty())
                std::snprintf(place, sizeof(place), "%s", "?");
            else
                std::snprintf(place, sizeof(place), "%s:%u", base.c_str(),
                              frames[k].line);
            /* Se parte para que quepa SOLO si el destino es una consola: a un
             * fichero va de una pieza, porque ahi lo que se hace es `grep` y
             * una linea partida deja de casar.  Ver `wrap`. */
            std::vector<std::string> defs;
            const std::string line =
                std::string(frames[k].inlined ? "" : "[la funcion real] ") +
                abbreviate_repeats(
                    frames[k].function != nullptr
                        ? readable(frames[k].function)
                        : std::string("(sin nombre)"),
                    defs);
            out.add("        %-28s %s\n", place,
                    wrap(line, cols > 46 ? cols - 46 : 0, 46).c_str());
            /* Y debajo, que significa cada abreviatura.  Van con el nombre
             * entero: lo que se quito de la linea esta aqui, no perdido. */
            for (const std::string &d : defs)
                out.add("%*s%s\n", 48, "",
                        wrap(d, cols > 48 ? cols - 48 : 0, 53).c_str());
        }
    }

    /* De donde cuelgan las rutas cortas de las cabeceras.  Sin esto, un
     * `bits/stl_vector.h:346` no se puede abrir. */
    if (!roots.empty()) {
        out.add("\n[reservas] las rutas de arriba cuelgan de:\n");
        for (const std::string &r : roots) out.add("      %s\n", r.c_str());
    }

    /* EL REPARTO POR MODULO, que es la lectura que la lista de sitios no da:
     * cuatrocientas filas dicen quien reserva mas, pero no si el grueso se lo
     * lleva la libreria estandar, una libreria de fuera o un modulo nuestro --
     * y esa es la cifra con la que se decide donde mirar --. */
    if (!by_module.empty()) {
        std::sort(by_module.begin(), by_module.end(),
                  [](const ModuleTotal &a, const ModuleTotal &b) {
                      return a.allocs > b.allocs;
                  });
        out.add( "\n[reservas] reparto por modulo y libreria:\n");
        out.add( "  %12s %6s %10s  %s\n", "reservas", "% ", "MiB",
                     "de quien es el codigo");
        for (const ModuleTotal &m : by_module)
            out.add( "  %12llu %5.1f%% %10.1f  %s\n",
                         (unsigned long long)m.allocs,
                         total == 0 ? 0.0
                                    : 100.0 * double(m.allocs) / double(total),
                         double(m.bytes) / (1024.0 * 1024.0), m.name.c_str());
        out.add(
                     "  se atribuye al marco de MAS AFUERA de cada sitio, que "
                     "es la funcion que existe en el binario: los de dentro son "
                     "plantillas de `std::` instanciadas con tipos nuestros.\n"
                     "  `sin clasificar` es lo que no tiene informacion de "
                     "depuracion; `libstdc++?` es una suposicion por el nombre, "
                     "no un dato.\n\n");
    }

    out.add(
                 "  %12llu %5.1f%% %10.1f            <- suma de los %u pares "
                 "(sitio, proposito) apuntados, sobre %llu reservas\n",
                 (unsigned long long)total_allocs,
                 total == 0 ? 0.0 : 100.0 * double(total_allocs) / double(total),
                 double(total_bytes) / (1024.0 * 1024.0), n,
                 (unsigned long long)total);
    /* Un porcentaje por encima de 100 no se puede dejar pasar como si fuera una
     * escala rara: significa que la tabla y el contador no hablan de lo mismo,
     * y hasta saber cual de los dos falla el resto del informe no se puede
     * leer.  Se dice, con las cifras que lo acotan. */
    /* CON UN MARGEN, y no por comodidad: las tres cifras se leen uno detras de
     * otro y el propio informe reserva por el camino, asi que un punado de
     * diferencia es la lectura y no un descuadre.  Lo que hay que cantar es un
     * desvio de verdad -- el que hubo aqui era del 124% --, no dos reservas. */
    const uint64_t margin = total / 64 + 16;
    if (total != 0 && total_allocs > total + margin)
        out.add(
                     "  NOTE: that is over 100%%.  The three figures do not "
                     "agree: %llu entries into operator new, %llu recorded + "
                     "%llu dropped, %llu allocations counted.  Until they do, "
                     "the percentages above are over the wrong base\n",
                     (unsigned long long)entries_at_snapshot,
                     (unsigned long long)total_allocs,
                     (unsigned long long)skipped, (unsigned long long)total);
    out.add(
                 "  sin declarar proposito: %llu de %llu (%.1f%%) -- eso es lo "
                 "que queda por migrar\n",
                 (unsigned long long)untagged, (unsigned long long)total,
                 total == 0 ? 0.0 : 100.0 * double(untagged) / double(total));
    out.add(
                 "  la columna FORMA esta medida; el otro eje -- cuanto VIVE lo "
                 "de cada sitio -- sale del par reserva/liberacion, que es la "
                 "fase 4 del plan y aun no esta\n");
    const uint64_t evicted = alloc_sites_overflow();
    if (evicted != 0)
        out.add(
                     "  %llu reservas encontraron su ventana llena y "
                     "desalojaron a la mas floja: lo que hereda el que entra ya "
                     "va DESCONTADO de las cifras de arriba, asi que son lo que "
                     "cada sitio se gano y no una cota superior\n",
                     (unsigned long long)evicted);

    /* Y AQUI sale todo, de una vez.  Vaciar antes de volver importa: esto corre
     * desde un manejador de salida y detras de el ya no queda nadie que lo
     * haga. */
    out.flush();

    /* Y si ademas se pidio una carpeta, lo MISMO en CSV para mirarlo con
     * `vesta_alloc/tools/alloc_tree.py`.  El volcado lo hace el asignador --
     * es suyo el dato --; lo unico que pone este lado son los nombres, por el
     * gancho.  Va DESPUES del informe de texto a proposito: si algo falla al
     * escribir ficheros, el informe legible ya salio. */
    const std::string &dir = flag_text(FlagId::HostAllocCsv);
    if (!dir.empty()) {
        // El gancho ya esta puesto, arriba: lo necesita tambien el informe de
        // texto, no solo esto.
        if (write_alloc_csv(dir.c_str()))
            std::fprintf(stderr, "[reservas] CSV escrito en %s\n", dir.c_str());
    }
}

} // namespace util
