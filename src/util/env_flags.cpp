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

#include "util/fnv.h"

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
    long number = 0;      ///< ya convertido, para no repetir el parseo.
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
            const long n = std::strtol(raw, &fin, 10);
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

long flag_int(FlagId id, long si_falta) {
    const FlagValue &fv = table().v[idx(id)];
    return fv.present ? fv.number : si_falta;
}

const std::string &flag_text(FlagId id) {
    if (kFlags[idx(id)].kind == FlagKind::TextLive) {
        /* Se relee.  En un buffer POR HILO, no en la tabla: los modulos se
         * compilan en paralelo y escribir la tabla compartida en una consulta
         * seria una carrera.
         *
         * Y un PUNTERO a nulo, no un `thread_local std::string`.  Este ultimo
         * tiene inicializador dinamico, que genera una variable de GUARDA, y en
         * MinGW esa guarda cuelga: el proceso se queda bloqueado antes incluso
         * de entrar en `main`.  Paso aqui y ya habia pasado antes en el
         * acumulador de tramos -- ver el comentario de `util/crono_tramo.cpp`,
         * que cuenta el mismo caso.  Un puntero a `nullptr` es de
         * inicializacion CONSTANTE: no hay guarda, y el alta se hace a mano. */
        static thread_local std::string *vivo = nullptr;
        if (vivo == nullptr) vivo = new std::string();
        const char *raw = std::getenv(kFlags[idx(id)].name);
        vivo->assign(raw ? raw : "");
        return *vivo;
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

} // namespace util
