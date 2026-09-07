/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/env_flags.cpp
 * @brief Lectura unica de los mandos del entorno y sus huellas por dominio.
 *        Ver @c util/env_flags.h.
 */

#include "util/env_flags.h"

#include <cstdio>
#include <ostream>

#include "util/fnv.h"
#include "util/thread_owned.h" // el buffer por hilo, sin `thread_local`

#include <array>
#include <cstdlib>
#include <cstring>
#include <string>

namespace util {

namespace {

/// La tabla, expandida de la misma linea que genero el enum.  Plana e indexada
/// por @c FlagId: es una busqueda por indice, no por nombre.
constexpr FlagInfo kFlags[] = {
#define VESTA_ENV_FLAG(id, nombre, alcance, dominio, tipo, so)                 \
    {nombre, FlagScope::alcance, FlagDomain::dominio, FlagKind::tipo,          \
     FlagOs::so},
#include "util/env_flags_table.h"
#undef VESTA_ENV_FLAG
};

static_assert(sizeof(kFlags) / sizeof(kFlags[0]) == kFlagCount,
              "la tabla y el enum salen de la misma linea: si esto salta, "
              "alguien los separo");

/// Lo leido del entorno para UN mando.
struct FlagValue {
    std::string text;     ///< tal cual venia; vacio si no estaba puesto.
    int64_t number = 0;   ///< ya convertido, para no repetir el parseo.
    bool present = false; ///< estaba definido (aunque fuera a "0").
    bool on = false;      ///< definido, no vacio y distinto de "0".
};

/// Todos los valores.  Se llena UNA vez.
struct FlagTable {
    std::array<FlagValue, kFlagCount> v;

    FlagTable() { load(); }

    void load() {
        for (size_t i = 0; i < kFlagCount; ++i) {
            FlagValue &fv = v[i];
            fv = FlagValue{};
            const char *raw = std::getenv(kFlags[i].name);
            if (raw == nullptr) continue;
            fv.present = true;
            fv.text = raw;
            /* UN solo criterio de "puesto", para todos.  Antes lo decidia cada
             * sitio: unos miraban solo que existiera, otros que no fuera "0" y
             * otros que fuera exactamente "1" -- con lo que `X=2` encendia unos
             * mandos y dejaba otros apagados. */
            fv.on = raw[0] != '\0' && !(raw[0] == '0' && raw[1] == '\0');
            char *fin = nullptr;
            /* `strtoll` y no `strtol`: en Windows un `long` mide 32 bits y
             * `strtol("4294967295")` se queda en 2147483647 SIN DECIRLO.  Ese
             * recorte callado es la mitad de por que `VESTA_JIT_THRESHOLD` no
             * funcionaba; la otra mitad estaba en su comprobacion de rango
             * (ver la nota en `auto_jit.cpp`). */
            const int64_t n = static_cast<int64_t>(std::strtoll(raw, &fin, 10));
            if (fin != raw) fv.number = n;
        }
    }
};

/// Vive lo que el proceso.  Se construye la primera vez que alguien pregunta,
/// que es antes de que nada dependa de un mando.
FlagTable &table() {
    static FlagTable t;
    return t;
}

/// Texto vacio compartido, para poder devolver una referencia estable cuando el
/// mando no esta puesto.
const std::string &empty_text() {
    static const std::string s;
    return s;
}

inline size_t idx(FlagId id) {
    return static_cast<size_t>(id);
}

} // namespace

bool flag_applies_here(FlagOs os) {
    if (os == FlagOs::Any) return true;
#if defined(_WIN32)
    return os == FlagOs::Windows;
#else
    return os == FlagOs::Posix;
#endif
}

const FlagInfo &flag_info(FlagId id) {
    return kFlags[idx(id)];
}

bool flag_on(FlagId id) {
    const FlagValue &fv = table().v[idx(id)];
    /* El defecto lo dice la TABLA, no el sitio que pregunta.  Un camino que ya
     * es el normal conserva su salida a mano (`X=0`) para poder compararlo con
     * el viejo, y eso no es lo mismo que un mando apagado que se enciende. */
    if (kFlags[idx(id)].kind == FlagKind::BoolOn)
        return !(fv.present && fv.text == "0");
    return fv.on;
}

bool flag_present(FlagId id) {
    return table().v[idx(id)].present;
}

int64_t flag_int(FlagId id, int64_t si_falta) {
    const FlagValue &fv = table().v[idx(id)];
    return fv.present ? fv.number : si_falta;
}

/* El buffer relido, uno POR HILO.  No en la tabla compartida: los modulos se
 * compilan en paralelo y escribirla en una consulta seria una carrera.
 *
 * Y por RANURA, no con `thread_local std::string`.  Este ultimo tiene
 * inicializador dinamico, que genera una variable de GUARDA, y en MinGW esa
 * guarda cuelga: el proceso se queda bloqueado antes incluso de entrar en
 * `main`.  Paso aqui y ya habia pasado antes en el acumulador de tramos -- ver
 * el comentario de `util/crono_tramo.cpp`, que cuenta el mismo caso.
 *
 * A nivel de FICHERO y no como estatico dentro de la funcion: un estatico local
 * con constructor no trivial genera esa misma guarda.  Ver
 * `util/thread_owned.h`. */
static ThreadOwned<std::string> g_live_text;

const std::string &flag_text(FlagId id) {
    if (kFlags[idx(id)].kind == FlagKind::TextLive) {
        std::string &s = g_live_text.get();
        const char *raw = std::getenv(kFlags[idx(id)].name);
        s.assign(raw ? raw : "");
        return s;
    }
    const FlagValue &fv = table().v[idx(id)];
    return fv.present ? fv.text : empty_text();
}

/**
 * @brief Mezcla un mando puesto en la huella que se esta construyendo.
 *
 * Entra el NOMBRE y no el indice: asi reordenar la tabla o meter un mando en
 * medio no cambia las claves ya escritas en disco.  Un cache que se invalida
 * entero porque alguien ordeno una lista no es un cache.
 */
static uint64_t mix_flag(uint64_t h, const FlagInfo &info,
                         const FlagValue &fv) {
    h = fnv_bytes(h, info.name, std::strlen(info.name));
    h = fnv_bytes(h, fv.text.data(), fv.text.size());
    return h;
}

uint64_t domain_fingerprint(FlagDomain domain) {
    uint64_t h = 0;
    bool alguno = false;
    for (size_t i = 0; i < kFlagCount; ++i) {
        if (kFlags[i].domain != domain) continue;
        if (kFlags[i].scope != FlagScope::Emitted) continue;
        const FlagValue &fv = table().v[i];
        if (!fv.present) continue;
        if (!alguno) {
            h = kFnvOffset;
            alguno = true;
        }
        h = mix_flag(h, kFlags[i], fv);
    }
    /* Cero cuando no hay ninguno puesto, que es el caso normal.  Devolver la
     * semilla del hash en su lugar meteria un numero arbitrario en las claves
     * de todo el mundo sin que nadie haya tocado nada. */
    return alguno ? h : 0;
}

uint64_t emitted_fingerprint() {
    uint64_t h = 0;
    bool alguno = false;
    for (size_t i = 0; i < kFlagCount; ++i) {
        if (kFlags[i].scope != FlagScope::Emitted) continue;
        const FlagValue &fv = table().v[i];
        if (!fv.present) continue;
        if (!alguno) {
            h = kFnvOffset;
            alguno = true;
        }
        h = mix_flag(h, kFlags[i], fv);
    }
    return alguno ? h : 0;
}

std::string emitted_flags_summary() {
    std::string out;
    for (size_t i = 0; i < kFlagCount; ++i) {
        if (kFlags[i].scope != FlagScope::Emitted) continue;
        const FlagValue &fv = table().v[i];
        if (!fv.present) continue;
        if (!out.empty()) out += ' ';
        out += kFlags[i].name;
        out += '=';
        out += fv.text;
    }
    return out;
}

void reload_flags_for_testing() {
    table().load();
}

const char *flag_scope_name(FlagScope s) {
    switch (s) {
    case FlagScope::Emitted: return "emitido";
    case FlagScope::Speed: return "velocidad";
    case FlagScope::Report: return "informe";
    case FlagScope::Runtime: return "ejecucion";
    case FlagScope::Location: return "ruta";
    case FlagScope::System: return "sistema";
    }
    return "?";
}

const char *flag_domain_name(FlagDomain d) {
    switch (d) {
    case FlagDomain::None: return "general";
    case FlagDomain::Optimizer: return "optimizador";
    case FlagDomain::Range: return "rangos";
    case FlagDomain::Alias: return "alias";
    case FlagDomain::Escape: return "escape";
    case FlagDomain::Loop: return "bucles";
    case FlagDomain::Vector: return "vectorizacion";
    case FlagDomain::Branch: return "saltos";
    case FlagDomain::Asm: return "ensamblador";
    case FlagDomain::Comptime: return "comptime";
    case FlagDomain::Scheduler: return "planificador";
    case FlagDomain::RegAlloc: return "registros";
    case FlagDomain::Codegen: return "generacion";
    case FlagDomain::Jit: return "jit";
    case FlagDomain::Gc: return "memoria";
    case FlagDomain::Parallel: return "paralelo";
    case FlagDomain::Asa: return "asa";
    case FlagDomain::Cache: return "cache";
    case FlagDomain::Paths: return "rutas";
    case FlagDomain::Count_: break;
    }
    return "?";
}

const char *flag_kind_name(FlagKind k) {
    switch (k) {
    case FlagKind::Bool: return "0/1";
    case FlagKind::BoolOn: return "0/1 (por defecto SI)";
    case FlagKind::Int: return "entero";
    case FlagKind::Text: return "texto";
    case FlagKind::TextLive: return "texto (se relee)";
    }
    return "?";
}

void print_env_flags(std::ostream &out) {
    out << "Variables de entorno declaradas: " << kFlagCount << "\n"
        << "  [*] = puesta ahora mismo.  El ALCANCE dice que cambia: "
           "'emitido' entra en la\n"
           "  huella de lo compilado -- dos valores distintos son dos "
           "artefactos distintos --;\n"
           "  el resto no.\n";

    for (unsigned d = 0; d < static_cast<unsigned>(FlagDomain::Count_); ++d) {
        const FlagDomain dom = static_cast<FlagDomain>(d);
        bool titled = false;
        for (size_t i = 0; i < kFlagCount; ++i) {
            const FlagInfo &f = kFlags[i];
            if (f.domain != dom) continue;
            /* Las que no existen en este sistema se dicen igual, marcadas: que
             * no salgan haria pensar que no existen, y quien lea la ayuda en
             * Windows para usarla en Linux se quedaria sin saberlo. */
            const bool here = flag_applies_here(f.os);
            const bool set = flag_present(static_cast<FlagId>(i));
            if (!titled) {
                out << "\n  " << flag_domain_name(dom) << ":\n";
                titled = true;
            }
            char line[256];
            std::snprintf(line, sizeof(line), "    %s %-34s %-10s %-22s%s",
                          set ? "[*]" : "   ", f.name,
                          flag_kind_name(f.kind), flag_scope_name(f.scope),
                          here ? "" : "  (no en este sistema)");
            out << line << "\n";
        }
    }
}

} // namespace util
