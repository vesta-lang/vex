/**
 * @file contract_when.cpp
 * @brief Implementacion del `when:` de un contrato (ver contract_when.h).
 */
#include "vx/contract_when.h"

#include <algorithm>
#include <cctype>

namespace vx {
namespace cwhen {

namespace {

/// Recorta espacios por los dos lados.
std::string trim(const std::string &s) {
    const size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return std::string();
    const size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

/**
 * @brief Parser de la expresion de un `when:`.
 *
 * Recursivo descendente sobre la gramatica:
 *   or   := and ('||' and)*
 *   and  := un ('&&' un)*
 *   un   := '!' un | '(' or ')' | atomo
 *
 * El unico punto delicado son los parentesis: los de un predicado van PEGADOS
 * a su nombre (`is_float<T>()`) y son parte del atomo, mientras que los de
 * agrupacion aparecen donde se espera una expresion.  Se distinguen por
 * posicion, no por contenido.
 *
 * No evalua: llama a @c ev por cada atomo.  Asi el mismo parser vale para
 * evaluar de verdad y para razonar con asignaciones hipoteticas.
 */
struct Parser {
    const std::string &s;
    size_t i = 0;
    const AtomEval &ev;
    bool &ok;

    Parser(const std::string &spec, const AtomEval &e, bool &o)
        : s(spec), ev(e), ok(o) {}

    void espacios() {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
            ++i;
    }

    bool p_atomo() {
        espacios();
        if (i < s.size() && s[i] == '(') {
            ++i; // agrupacion
            const bool v = p_or();
            espacios();
            if (i < s.size() && s[i] == ')')
                ++i;
            else
                ok = false;
            return v;
        }
        const size_t ini = i;
        int d = 0;
        while (i < s.size()) {
            const char c = s[i];
            if (c == '(') {
                ++d;
            } else if (c == ')') {
                if (d == 0) break; // cierra una agrupacion de fuera
                --d;
            } else if (d == 0 && (c == '&' || c == '|')) {
                break;
            }
            ++i;
        }
        const std::string at = trim(s.substr(ini, i - ini));
        if (at.empty()) {
            ok = false;
            return false;
        }
        return ev(at, ok);
    }

    bool p_un() {
        espacios();
        if (i < s.size() && s[i] == '!') {
            ++i;
            return !p_un();
        }
        return p_atomo();
    }

    bool p_and() {
        bool v = p_un();
        for (;;) {
            espacios();
            if (i + 1 < s.size() && s[i] == '&' && s[i + 1] == '&') {
                i += 2;
                const bool r = p_un(); // sin corto-circuito: hay que VER todos
                v = v && r;            // los atomos (los recolecta @c atoms)
            } else {
                break;
            }
        }
        return v;
    }

    bool p_or() {
        bool v = p_and();
        for (;;) {
            espacios();
            if (i + 1 < s.size() && s[i] == '|' && s[i + 1] == '|') {
                i += 2;
                const bool r = p_and();
                v = v || r;
            } else {
                break;
            }
        }
        return v;
    }
};

/// Tope de atomos distintos al comparar especificidad: la tabla de verdad es
/// 2^N.  Con 16 son 65536 filas (instantaneo) y ninguna expresion razonable se
/// acerca; pasado eso, se dice que no se puede decidir en vez de colgarse.
constexpr size_t kMaxAtomos = 16;

} // namespace

bool eval(const std::string &spec, const AtomEval &ev, bool &ok) {
    const std::string t = trim(spec);
    if (t.empty()) return true; // sin `when:` = siempre
    Parser p(t, ev, ok);
    const bool v = p.p_or();
    p.espacios();
    if (p.i != t.size()) ok = false; // sobra texto -> mal formada
    return v;
}

bool atoms(const std::string &spec, std::vector<std::string> &out) {
    out.clear();
    bool ok = true;
    // Se "evalua" solo para recorrer: cada atomo se anota y se devuelve false.
    // El resultado da igual; lo que importa es el recorrido, y por eso el
    // parser no corto-circuita.
    AtomEval rec = [&](const std::string &at, bool &) -> bool {
        if (std::find(out.begin(), out.end(), at) == out.end())
            out.push_back(at);
        return false;
    };
    (void)eval(spec, rec, ok);
    return ok;
}

const std::vector<std::string> &target_keys() {
    // Las mismas de @Target.  `mode` lo fija la CLI (-m jit/vm/auto), `os` y
    // `arch` el driver AOT cuando genera para otro target, `cpu` el cpuid.
    static const std::vector<std::string> k = {"os", "arch", "cpu", "mode"};
    return k;
}

const std::vector<std::string> &target_vars() {
    static const std::vector<std::string> k = {"compiler", "vm"};
    return k;
}

const std::vector<std::string> &type_preds() {
    static const std::vector<std::string> k = {
        "is_float", "is_integer", "is_pointer", "is_signed", "sizeof"};
    return k;
}

const std::vector<std::string> &known_archs() {
    // Las que el registro de objetivos define (@ref aot::AotArch).  Estaban
    // solo tres, y `arch:x86_16` ya se escribia en siete sitios del arbol sin
    // figurar aqui: un registro que dice ser cerrado y no lo esta no puede
    // distinguir una arquitectura que falta de uno mal escrito.
    static const std::vector<std::string> k = {"x86_64", "x86",   "x86_16",
                                               "arm64",  "arm32", "riscv64"};
    return k;
}

std::string normalize_arch(const std::string &spelling) {
    // Las grafias que llegan de la linea de ordenes, de la API C y de los
    // ficheros de proyecto.  Estaban escritas por separado en cada sitio que
    // las necesitaba, y una de esas copias decidia la arquitectura con un
    // booleano -- "si no es de 32 bits, es x86-64" -- de modo que pedir
    // aarch64 evaluaba los `@Target` como si fuera x86-64 y seleccionaba las
    // variantes de otra maquina sin decir nada.
    if (spelling == "x86-64" || spelling == "x86_64" || spelling == "x64" ||
        spelling == "amd64")
        return "x86_64";
    if (spelling == "x86-32" || spelling == "x86_32" || spelling == "x86" ||
        spelling == "i386")
        return "x86";
    if (spelling == "arm64" || spelling == "aarch64") return "arm64";
    if (spelling == "arm32" || spelling == "armv7" || spelling == "arm")
        return "arm32";
    if (spelling == "x86-16" || spelling == "x86_16" || spelling == "i8086" ||
        spelling == "real")
        return "x86_16";
    if (spelling == "riscv64" || spelling == "riscv" || spelling == "rv64")
        return "riscv64";
    // Desconocida: se devuelve intacta y no casara con ningun atomo.
    return spelling;
}

AtomKind atom_kind(const std::string &atomo, std::string *esperado) {
    const std::string a = trim(atomo);
    auto en = [](const std::vector<std::string> &v, const std::string &s) {
        return std::find(v.begin(), v.end(), s) != v.end();
    };
    auto ident_hasta = [&](size_t fin) {
        std::string id = trim(a.substr(0, fin));
        return id;
    };
    auto es_ident = [](const std::string &s) {
        if (s.empty()) return false;
        if (!(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_'))
            return false;
        for (char c : s)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_'))
                return false;
        return true;
    };

    // Forma `pred<...>(...)`: el '<' va antes que cualquier ':' o comparador.
    const size_t lt = a.find('<');
    const size_t dp = a.find(':');
    if (lt != std::string::npos && (dp == std::string::npos || lt < dp)) {
        const std::string pred = ident_hasta(lt);
        if (es_ident(pred) && en(type_preds(), pred)) return AtomKind::TIPO;
        if (esperado)
            *esperado = es_ident(pred)
                            ? ("predicado desconocido '" + pred + "'")
                            : "predicado mal formado";
        return AtomKind::DESCONOCIDO;
    }

    // Forma `clave:valor`.
    if (dp != std::string::npos) {
        const std::string clave = ident_hasta(dp);
        if (es_ident(clave) && en(target_keys(), clave)) {
            if (trim(a.substr(dp + 1)).empty()) {
                if (esperado)
                    *esperado = "falta el valor tras '" + clave + ":'";
                return AtomKind::DESCONOCIDO;
            }
            return AtomKind::TARGET;
        }
        if (esperado)
            *esperado = es_ident(clave) ? ("clave desconocida '" + clave + "'")
                                        : "clave mal formada";
        return AtomKind::DESCONOCIDO;
    }

    // Forma `variable OP version`.
    const size_t op = a.find_first_of("<>=!");
    if (op != std::string::npos) {
        const std::string var = ident_hasta(op);
        if (es_ident(var) && en(target_vars(), var)) return AtomKind::TARGET;
        if (esperado)
            *esperado = es_ident(var) ? ("variable desconocida '" + var + "'")
                                      : "variable mal formada";
        return AtomKind::DESCONOCIDO;
    }

    if (esperado)
        *esperado = "no es ni `clave:valor`, ni `variable OP version`, "
                    "ni `predicado<T>()`";
    return AtomKind::DESCONOCIDO;
}

bool only_target(const std::string &spec) {
    std::vector<std::string> at;
    if (!atoms(spec, at)) return false;
    for (const auto &a : at)
        if (atom_kind(a) != AtomKind::TARGET) return false;
    return true;
}

void resolve(const std::vector<ast::PendingComplexity> &decls,
             const AtomEval &ev, const ErrFn &err, Resolved &out) {
    // Que `when:` escribio cada campo, para poder comparar especificidad
    // cuando llegue otro que quiera el mismo.  Ausente = campo sin escribir.
    struct Campo {
        std::string *valor;
        const char *nombre;
        bool escrito = false;
        std::string por; // el `when:` que lo escribio
    };
    Campo campos[] = {
        {&out.expr, "O(...)"},
        {&out.partial_pre, "partial_pre"},
        {&out.partial_post, "partial_post"},
        {&out.total_pre, "total_pre"},
        {&out.total_post, "total_post"},
    };
    const size_t N = sizeof(campos) / sizeof(campos[0]);

    for (const auto &d : decls) {
        bool ok = true;
        const bool casa = eval(d.when, ev, ok);
        if (!ok) {
            std::string detalle;
            std::vector<std::string> at;
            atoms(d.when, at);
            for (const auto &a : at) {
                std::string esp;
                if (atom_kind(a, &esp) == AtomKind::DESCONOCIDO) {
                    detalle = " ('" + a + "': " + esp + ")";
                    break;
                }
            }
            err("@complexity: no entiendo el `when: " + d.when + "'" + detalle);
            continue;
        }
        if (!casa) continue;

        const std::string *nuevos[] = {&d.expr, &d.partial_pre, &d.partial_post,
                                       &d.total_pre, &d.total_post};
        for (size_t i = 0; i < N; ++i) {
            if (nuevos[i]->empty()) continue; // esta decl no escribe el campo
            Campo &c = campos[i];
            if (!c.escrito) {
                *c.valor = *nuevos[i];
                c.escrito = true;
                c.por = d.when;
                if (i == 0 && !d.vars.empty()) out.vars = d.vars;
                continue;
            }
            // Los dos escriben el mismo campo: decide la especificidad, NUNCA
            // el orden textual.
            bool cok = true;
            const Spec r = compare(d.when, c.por, cok);
            if (!cok || r == Spec::AMBIGUAS) {
                auto muestra = [](const std::string &w) {
                    return w.empty() ? std::string("<sin when>")
                                     : ("when: " + w);
                };
                err(std::string("@complexity: dos contratos escriben '") +
                    c.nombre + "' y ninguno es mas especifico que el otro (" +
                    muestra(c.por) + " y " + muestra(d.when) +
                    "); acota uno de los dos para desempatar");
                continue;
            }
            if (r == Spec::B_MAS)
                continue; // el que ya estaba es mas especifico
            // A_MAS o IGUALES -> escribe el nuevo (entre condiciones
            // equivalentes, la ultima; no hay nada que distinguirlas).
            *c.valor = *nuevos[i];
            c.por = d.when;
            if (i == 0 && !d.vars.empty()) out.vars = d.vars;
        }
    }
}

Spec compare(const std::string &a, const std::string &b, bool &ok) {
    ok = true;
    const std::string ta = trim(a);
    const std::string tb = trim(b);

    // Union de atomos.  La vacia (`true`) no aporta ninguno.
    std::vector<std::string> ua, ub;
    if (!atoms(ta, ua) || !atoms(tb, ub)) {
        ok = false;
        return Spec::AMBIGUAS;
    }
    std::vector<std::string> todos = ua;
    for (const auto &x : ub)
        if (std::find(todos.begin(), todos.end(), x) == todos.end())
            todos.push_back(x);
    if (todos.size() > kMaxAtomos) {
        ok = false;
        return Spec::AMBIGUAS;
    }

    // Tabla de verdad: A implica B si no hay ninguna fila con A y sin B.
    bool a_implica_b = true;
    bool b_implica_a = true;
    const size_t filas = static_cast<size_t>(1) << todos.size();
    for (size_t m = 0; m < filas; ++m) {
        AtomEval asigna = [&](const std::string &at, bool &o) -> bool {
            for (size_t k = 0; k < todos.size(); ++k)
                if (todos[k] == at) return (m >> k) & 1u;
            o = false; // no deberia pasar: `todos` sale de las dos expresiones
            return false;
        };
        bool oka = true, okb = true;
        const bool va = eval(ta, asigna, oka);
        const bool vb = eval(tb, asigna, okb);
        if (!oka || !okb) {
            ok = false;
            return Spec::AMBIGUAS;
        }
        if (va && !vb) a_implica_b = false;
        if (vb && !va) b_implica_a = false;
        if (!a_implica_b && !b_implica_a) break; // ya no puede cambiar
    }

    if (a_implica_b && b_implica_a) return Spec::IGUALES;
    if (a_implica_b) return Spec::A_MAS;
    if (b_implica_a) return Spec::B_MAS;
    return Spec::AMBIGUAS;
}

void resolve_footprint(const std::vector<ast::PendingFootprint> &decls,
                       const ResolvedFP &base, const AtomEval &ev,
                       const ErrFn &err, ResolvedFP &out) {
    out = base;

    // Por campo: quien lo escribio (para comparar especificidad con el
    // siguiente).  `escrito` false = solo esta el default de `base`, cuyo
    // `when:` implicito es vacio (siempre) -> lo menos especifico.
    struct Campo {
        bool escrito = false;
        std::string por;
    };
    Campo cpure, cnothrow, cnopanic, calloc, calloc_p, cstack, cstack_p;

    // Aplica un campo de un pending que ha casado: si nadie lo habia escrito
    // con un `when:`, gana sobre el default; si ya lo escribio otro `when:`,
    // decide la especificidad.  `nombre` es para el mensaje de ambiguedad.
    auto aplicar = [&](Campo &c, const std::string &when, const char *nombre,
                       const std::function<void()> &set) {
        if (!c.escrito) {
            set();
            c.escrito = true;
            c.por = when;
            return;
        }
        bool ok = true;
        const Spec r = compare(when, c.por, ok);
        if (!ok || r == Spec::AMBIGUAS) {
            auto muestra = [](const std::string &w) {
                return w.empty() ? std::string("<sin when>") : ("when: " + w);
            };
            err(std::string("@") + nombre +
                ": dos contratos lo declaran y ninguno es mas especifico que "
                "el "
                "otro (" +
                muestra(c.por) + " y " + muestra(when) +
                "); acota uno de los dos para desempatar");
            return;
        }
        if (r == Spec::B_MAS) return; // el que estaba es mas especifico
        set();                        // A_MAS o IGUALES -> el nuevo
        c.por = when;
    };

    for (const auto &d : decls) {
        bool ok = true;
        const bool casa = eval(d.when, ev, ok);
        if (!ok) {
            std::string detalle;
            std::vector<std::string> at;
            atoms(d.when, at);
            for (const auto &a : at) {
                std::string esp;
                if (atom_kind(a, &esp) == AtomKind::DESCONOCIDO) {
                    detalle = " ('" + a + "': " + esp + ")";
                    break;
                }
            }
            err("contrato de huella: no entiendo el `when: " + d.when + "'" +
                detalle);
            continue;
        }
        if (!casa) continue;
        if (d.pure >= 0)
            aplicar(cpure, d.when, "pure", [&] { out.pure = d.pure; });
        if (d.nothrow_ >= 0)
            aplicar(cnothrow, d.when, "nothrow",
                    [&] { out.nothrow_ = d.nothrow_; });
        if (d.nopanic >= 0)
            aplicar(cnopanic, d.when, "nopanic",
                    [&] { out.nopanic = d.nopanic; });
        if (d.alloc >= 0)
            aplicar(calloc, d.when, "alloc", [&] { out.alloc = d.alloc; });
        if (d.alloc_partial >= 0)
            aplicar(calloc_p, d.when, "alloc",
                    [&] { out.alloc_partial = d.alloc_partial; });
        if (d.stack >= 0)
            aplicar(cstack, d.when, "stack", [&] { out.stack = d.stack; });
        if (d.stack_partial >= 0)
            aplicar(cstack_p, d.when, "stack",
                    [&] { out.stack_partial = d.stack_partial; });
    }
}

} // namespace cwhen
} // namespace vx
