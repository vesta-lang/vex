/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/coste/test_coste_opcodes.cpp
 * @brief Deriva el coste de cada opcode del codigo maquina de sus handlers.
 *
 * Que problema resuelve
 * ---------------------
 * Hoy el nivel 3 de Big-O cuenta instrucciones de bytecode con peso 1: un
 * millon de `newobj` cuenta lo mismo que un millon de `add`.  Para pesarlas
 * hace falta saber lo que cuesta cada opcode, y ese numero tiene que salir
 * SIN tocar el interprete: nada de contadores, nada de hooks, ni una rama
 * mas en el bucle de despacho.
 *
 * Como lo consigue
 * ----------------
 * El truco es que este test ENLAZA la VM en vez de leer un binario.  Con eso:
 *
 *   - `decode_table_primary` / `decode_table_extended` se recorren tal cual,
 *     sin parsear fuente ni secciones: son datos del propio proceso.
 *   - Los campos `exec` y `decode` son punteros a funcion, o sea DIRECCIONES
 *     de codigo ya mapeado.  No hay que resolver simbolos ni entender PE/ELF.
 *   - Capstone desensambla directamente desde esa direccion.
 *   - `instr_db::analyze_asm_cost()` pone el coste por microarquitectura, con
 *     su modelo de puertos.  No se inventa ningun numero.
 *
 * Coste en la VM que se envia: CERO.  Nada de esto corre dentro del
 * interprete; el test lo mide desde fuera sobre el codigo ya compilado.
 *
 * Lo que este test NO afirma
 * --------------------------
 * Un handler con un bucle dependiente de datos -- strings, alloc, el recorrido
 * de vtable de `callvirt` -- tiene un coste estatico que es una COTA INFERIOR,
 * no un coste.  Se marca como tal en vez de publicarlo como si fuera exacto.
 * Y `analyze_asm_cost` devuelve `matched`/`costed`, asi que la cobertura real
 * se publica en vez de suponerse.
 */

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <capstone/capstone.h>
#include <json.hpp>

#include "runtime/decode_instruction.h"
#include "runtime/decode_table.h"
#include "util/ansi.h"
#include "vx/asm/instr_db.h"

namespace {

using vx::instr_db::Isa;

/// Hasta donde se sigue una cadena de llamadas antes de rendirse.  Sin tope,
/// un handler que llama al runtime entero arrastraria medio binario.
int g_profundidad = 6;

/// Tope de bytes por funcion.  Es una red de seguridad: si el recorrido no
/// encuentra el `ret` -- por datos entre codigo o por un salto que no se
/// sigue -- se para aqui en vez de leer memoria ajena.
constexpr size_t BYTES_MAX = 128 * 1024;

/// Que se pudo decir del coste de un handler.
enum class Certeza {
    Exacto,  ///< un solo bloque: el coste es el coste.
    Acotado, ///< solo saltos hacia adelante: calculable como maximo de caminos.
    Cota,    ///< bucle o llamada no seguida: el numero es una cota inferior.
};

const char *nombre_certeza(Certeza c) {
    switch (c) {
    case Certeza::Exacto: return "exacto";
    case Certeza::Acotado: return "acotado";
    default: return "cota";
    }
}

struct Handler {
    std::string cuerpo; ///< texto asm, para `analyze_asm_cost`.
    uint32_t instrs = 0;
    uint32_t saltos_atras = 0;
    uint32_t saltos_adelante = 0;
    uint32_t llamadas = 0;
    bool truncado = false; ///< se llego al tope sin ver el final.
};

/// Desensambla desde @p dir hasta el final de la funcion, siguiendo las
/// llamadas hasta @p profundidad.
///
/// El final es un `ret`, o un `jmp` fuera del rango recorrido (tail call: el
/// optimizador saca cuerpo comun a funciones aparte, y sin seguirlo se mide un
/// stub de tres instrucciones en vez del trabajo).
void recorrer(csh cs, uint64_t dir, int profundidad, Handler &h,
              std::set<uint64_t> &vistas) {
    if (profundidad < 0 || dir == 0 || !vistas.insert(dir).second) return;

    const uint8_t *code = reinterpret_cast<const uint8_t *>(dir);
    size_t restante = BYTES_MAX;
    uint64_t addr = dir;
    cs_insn *insn = cs_malloc(cs);
    if (!insn) return;

    const uint64_t lo = dir;
    uint64_t hi = dir;
    std::vector<uint64_t> pendientes; // llamadas a seguir despues

    while (cs_disasm_iter(cs, &code, &restante, &addr, insn)) {
        h.instrs++;
        hi = insn->address;
        h.cuerpo += insn->mnemonic;
        if (insn->op_str[0]) {
            h.cuerpo += ' ';
            h.cuerpo += insn->op_str;
        }
        h.cuerpo += '\n';

        const std::string m = insn->mnemonic;
        // Destino inmediato del salto/llamada, si lo hay.  Un `jmp *%rax` no
        // lo tiene, y eso ya es motivo para no prometer exactitud.
        uint64_t destino = 0;
        if (insn->op_str[0] == '0' && insn->op_str[1] == 'x')
            destino = strtoull(insn->op_str + 2, nullptr, 16);

        if (m == "ret" || m == "retq") break;
        if (m == "call" || m == "callq") {
            h.llamadas++;
            if (destino) pendientes.push_back(destino);
            continue;
        }
        if (m[0] == 'j') {
            if (!destino) {
                h.llamadas++; // salto indirecto: se trata como no seguible
            } else if (destino <= insn->address && destino >= lo) {
                h.saltos_atras++; // bucle dentro de la funcion
            } else if (destino > hi && destino < lo + BYTES_MAX) {
                h.saltos_adelante++; // `if` dentro de la funcion
            } else if (m == "jmp") {
                // Tail call: el cuerpo de verdad esta ahi.
                pendientes.push_back(destino);
                break;
            }
        }
        if (h.instrs > 20000) {
            h.truncado = true;
            break;
        }
    }
    cs_free(insn, 1);

    for (uint64_t d : pendientes)
        recorrer(cs, d, profundidad - 1, h, vistas);
}

Certeza certeza_de(const Handler &h) {
    if (h.truncado || h.saltos_atras || h.llamadas) return Certeza::Cota;
    if (h.saltos_adelante) return Certeza::Acotado;
    return Certeza::Exacto;
}

struct Fila {
    std::string opcode; ///< mnemonico del opcode de la VM.
    std::string grupo;  ///< "exec" o "decode".
    const void *fn = nullptr;
    /// Cuantos opcodes comparten esta funcion.  En `exec` es 1; en `decode`
    /// llega a 87, y publicar la fila con el nombre de UNO de ellos haria
    /// creer que ese coste es suyo en exclusiva.
    uint32_t compartida = 1;
    Handler h;
    /// Coste en CADA microarquitectura de la ISA.  El mismo handler cuesta
    /// distinto en cada una -- es el mismo codigo, pero no la misma maquina --
    /// y publicar solo una escondia esa dispersion, que es justo lo que hay
    /// que ver antes de fijar pesos en el modelo.
    std::vector<vx::instr_db::AsmBlockCost> coste;
    Certeza certeza = Certeza::Cota;
};

/// Salida acumulada en memoria y volcada de una vez.
///
/// El informe son ~5600 lineas (232 opcodes x 24 filas), y con `printf` eso
/// es una llamada por linea: formateo, bloqueo del FILE* y descarga al
/// terminal cada vez.  En Windows es el caso peor -- cada escritura a la
/// consola cruza a la API del sistema -- y se notaba.
///
/// Aqui se compone todo en un `std::string` y se escribe con UN `fwrite`.
/// Ademas los numeros se formatean a mano en vez de con `snprintf`: son dos
/// enteros y un punto, y evitarlo quita otras ~17000 llamadas de formateo.
/// Portable: solo `std::string` y `fwrite`, sin nada especifico del sistema.
struct Salida {
    std::string b;

    Salida() { b.reserve(8u << 20); } // ~8 MB: cabe el informe entero

    Salida &s(const char *t) {
        b += t;
        return *this;
    }
    Salida &s(const std::string &t) {
        b += t;
        return *this;
    }
    Salida &ch(char c) {
        b += c;
        return *this;
    }
    Salida &nl() {
        b += '\n';
        return *this;
    }
    Salida &rep(char c, int n) {
        b.append(static_cast<size_t>(n < 0 ? 0 : n), c);
        return *this;
    }

    /// Texto alineado a la IZQUIERDA en @p ancho.  Se rellena con espacios y
    /// no se trunca por debajo: el color se anade FUERA, porque los codigos
    /// ANSI no ocupan ancho visible y meterlos dentro descuadra la columna.
    Salida &izq(const char *t, int ancho) {
        int n = 0;
        while (t[n]) {
            b += t[n];
            ++n;
        }
        return rep(' ', ancho - n);
    }

    /// Texto alineado a la DERECHA.  Hace falta para los rotulos de las
    /// columnas numericas: si la cabecera se alinea a la izquierda y los datos
    /// a la derecha, los titulos no caen sobre sus numeros -- y un rotulo mas
    /// largo que su campo se come el del vecino.
    Salida &der(const char *t, int ancho) {
        int n = 0;
        while (t[n])
            ++n;
        rep(' ', ancho - n);
        return s(t);
    }

    /// Entero sin signo alineado a la DERECHA.
    Salida &num(uint64_t v, int ancho) {
        char tmp[24];
        int n = 0;
        do {
            tmp[n++] = static_cast<char>('0' + v % 10);
            v /= 10;
        } while (v);
        rep(' ', ancho - n);
        while (n)
            b += tmp[--n];
        return *this;
    }

    /// Numero con UN decimal, alineado a la derecha.  Se redondea a la decima
    /// mas cercana con enteros, sin pasar por la conversion de `printf`.
    ///
    /// OJO: no da siempre lo mismo que `%.1f`.  En los empates exactos esto
    /// redondea hacia arriba y `printf` mira la representacion binaria del
    /// double: `9.95` sale aqui `10.0` y por `printf` `9.9`, porque el `9.95`
    /// que cabe en un double es un pelo menor.  Comprobado sobre once valores;
    /// solo difieren los empates.
    ///
    /// Se deja asi a proposito -- redondear .5 hacia arriba es lo que espera
    /// quien lee -- pero queda dicho para que nadie lo "arregle" al comparar
    /// esta salida con una generada por `printf`, y porque el JSON lleva el
    /// valor con toda su precision: la unica cifra redondeada es la del
    /// terminal.
    Salida &dec1(double v, int ancho) {
        const bool neg = v < 0.0;
        if (neg) v = -v;
        const uint64_t escalado = static_cast<uint64_t>(v * 10.0 + 0.5);
        const uint64_t ent = escalado / 10, frac = escalado % 10;
        char tmp[24];
        int n = 0;
        uint64_t e = ent;
        do {
            tmp[n++] = static_cast<char>('0' + e % 10);
            e /= 10;
        } while (e);
        rep(' ', ancho - n - 2 - (neg ? 1 : 0));
        if (neg) b += '-';
        while (n)
            b += tmp[--n];
        b += '.';
        b += static_cast<char>('0' + frac);
        return *this;
    }

    /// Vuelca y vacia.  Se llama una vez al final, o por tramos si hiciera
    /// falta acotar la memoria.
    void volcar(std::FILE *fp) {
        if (!b.empty()) std::fwrite(b.data(), 1, b.size(), fp);
        b.clear();
    }
};

/// La ISA de ESTE binario.  Los handlers son el codigo maquina del propio
/// interprete, asi que solo tiene sentido costearlos con la DB de la
/// arquitectura en la que se compilo: no se puede medir codigo x86 con las
/// latencias de ARM.
#if defined(__aarch64__) || defined(_M_ARM64)
constexpr Isa kIsa = Isa::ARM64;
constexpr cs_arch kCsArch = CS_ARCH_ARM64;
constexpr cs_mode kCsMode = CS_MODE_ARM;
constexpr const char *kIsaNombre = "AArch64";
#elif defined(__x86_64__) || defined(_M_X64)
constexpr Isa kIsa = Isa::X86;
constexpr cs_arch kCsArch = CS_ARCH_X86;
constexpr cs_mode kCsMode = CS_MODE_64;
constexpr const char *kIsaNombre = "x86-64";
#else
#error "ISA no soportada por el derivador de coste"
#endif

} // namespace

int main(int argc, char **argv) {
    // Se costea en TODAS las microarquitecturas de la ISA, no en una.  El
    // mismo handler cuesta distinto en cada una, y elegir una sola escondia
    // esa dispersion -- que es lo primero que hay que ver antes de fijar los
    // pesos del modelo.  El argumento opcional filtra a una sola.
    const std::string filtro = (argc > 1) ? argv[1] : "";
    if (argc > 2) g_profundidad = std::atoi(argv[2]);

    const uint32_t n_ua = vx::instr_db::microarch_count(kIsa);
    if (n_ua == 0) {
        std::printf("[error] la DB de coste de %s no trae "
                    "microarquitecturas.\n",
                    kIsaNombre);
        return 1;
    }
    std::vector<uint32_t> uarchs;
    if (filtro.empty()) {
        for (uint32_t i = 0; i < n_ua; ++i)
            uarchs.push_back(i);
    } else {
        const int32_t u = vx::instr_db::microarch_by_name(kIsa, filtro);
        if (u < 0) {
            std::printf("[error] microarquitectura desconocida: '%s'\n"
                        "        disponibles:",
                        filtro.c_str());
            for (uint32_t i = 0; i < n_ua; ++i)
                std::printf(" %s", vx::instr_db::microarch_name(kIsa, i));
            std::printf("\n");
            return 1;
        }
        uarchs.push_back(static_cast<uint32_t>(u));
    }

    csh cs;
    if (cs_open(kCsArch, kCsMode, &cs) != CS_ERR_OK) {
        std::printf("[error] no pude abrir Capstone.\n");
        return 1;
    }

    // Recorrer las DOS tablas.  Son datos de este mismo proceso: no hay que
    // parsear nada ni resolver simbolos.
    std::vector<Fila> filas;
    std::map<const void *, std::string> vistos_exec, vistos_decode;
    // Cuantos opcodes usan cada funcion.  Se cuenta en una pasada previa
    // porque la fila necesita el total, no el primero que aparecio.
    std::map<const void *, uint32_t> reparto;

    struct {
        runtime::InstrFormat *t;
        const char *nom;
    } tablas[] = {
        {runtime::decode_table_primary, "primary"},
        {runtime::decode_table_extended, "extended"},
    };

    for (auto &tb : tablas)
        for (int i = 0; i < 0x100; ++i) {
            const runtime::InstrFormat &f = tb.t[i];
            if (!f.exec) continue;
            reparto[(const void *)f.exec]++;
            if (f.decode) reparto[(const void *)f.decode]++;
        }

    for (auto &tb : tablas) {
        for (int i = 0; i < 0x100; ++i) {
            const runtime::InstrFormat &f = tb.t[i];
            if (!f.exec || !f.name) continue;
            const std::string nom = f.name[0] ? f.name : "(sin nombre)";

            // Un mismo `decode` sirve a decenas de opcodes -- 87 comparten
            // `decode_instr_two_op_reg` --, asi que se cuesta UNA vez.  Es la
            // diferencia entre 33 numeros y 219.
            for (auto par :
                 {std::make_pair((const void *)f.exec, "exec"),
                  std::make_pair((const void *)f.decode, "decode")}) {
                if (!par.first) continue;
                auto &cache = (std::strcmp(par.second, "exec") == 0)
                                  ? vistos_exec
                                  : vistos_decode;
                if (cache.count(par.first)) continue;
                cache[par.first] = nom;

                Fila fila;
                fila.opcode = nom;
                fila.grupo = par.second;
                fila.fn = par.first;
                fila.compartida = reparto[par.first];
                std::set<uint64_t> vistas;
                recorrer(cs, reinterpret_cast<uint64_t>(par.first),
                         g_profundidad, fila.h, vistas);
                if (fila.h.instrs == 0) continue;
                for (uint32_t u : uarchs)
                    fila.coste.push_back(
                        vx::instr_db::analyze_asm_cost(kIsa, fila.h.cuerpo, u));
                fila.certeza = certeza_de(fila.h);
                filas.push_back(std::move(fila));
            }
        }
    }
    cs_close(&cs);

    // --- El coste por INSTRUCCION DE LA VM --------------------------------
    // Lo de arriba son funciones; esto son opcodes, que es lo que se quiere
    // pesar.  No es lo mismo: un opcode cuesta su `exec` MAS su `decode`, y
    // como el `decode` lo comparten decenas de opcodes, la tabla de funciones
    // no permite leer el coste de ninguno sin cruzarla a mano.
    //
    // Los dos sumandos se publican por separado a proposito: el `exec` se
    // paga SIEMPRE, y el `decode` solo cuando la instruccion falla en la
    // icache.  El coste real de un sitio es
    //     exec + P_fallo * decode
    // y `P_fallo` no es una propiedad del opcode -- depende de que PCs
    // conviven en su bucle -- asi que no se puede meter aqui sin inventarla.
    std::map<const void *, const Fila *> por_fn_exec, por_fn_decode;
    for (const auto &f : filas)
        (f.grupo == "exec" ? por_fn_exec : por_fn_decode)[f.fn] = &f;

    struct Opcode {
        std::string nombre;
        const char *tabla;
        int indice;
        const Fila *ex = nullptr;
        const Fila *de = nullptr;
    };
    std::vector<Opcode> opcodes;
    for (auto &tb : tablas)
        for (int i = 0; i < 0x100; ++i) {
            const runtime::InstrFormat &f = tb.t[i];
            if (!f.exec || !f.name || !f.name[0]) continue;
            Opcode o;
            o.nombre = f.name;
            o.tabla = tb.nom;
            o.indice = i;
            auto ie = por_fn_exec.find((const void *)f.exec);
            if (ie != por_fn_exec.end()) o.ex = ie->second;
            if (f.decode) {
                auto id = por_fn_decode.find((const void *)f.decode);
                if (id != por_fn_decode.end()) o.de = id->second;
            }
            if (o.ex) opcodes.push_back(std::move(o));
        }

    if (filas.empty()) {
        std::printf("[error] no se pudo desensamblar ningun handler.\n");
        return 1;
    }

    // ---- Informe -------------------------------------------------------
    using namespace vx;
    const char *R = ansi::c(ansi::RESET);
    const char *B = ansi::c(ansi::BOLD);
    const char *D = ansi::c(ansi::DIM);
    const char *VE = ansi::c(ansi::GREEN);
    const char *AM = ansi::c(ansi::YELLOW);
    const char *RO = ansi::c(ansi::RED);
    const char *CI = ansi::c(ansi::CYAN);

    auto color_certeza = [&](Certeza c) {
        return c == Certeza::Exacto ? VE : (c == Certeza::Acotado ? AM : RO);
    };

    std::printf("%sCoste por opcode, derivado del codigo maquina%s\n", B, R);
    std::printf("  ISA                : %s%s%s\n", CI, kIsaNombre, R);
    std::printf("  microarquitecturas : %zu\n", uarchs.size());
    std::printf("  profundidad de llamadas: %d\n", g_profundidad);
    std::printf("  handlers costeados : %zu\n\n", filas.size());

    // --- Resumen por microarquitectura -----------------------------------
    // Va primero porque decide si el resto se puede leer: si una microarq
    // solo cuesta el 40% de las instrucciones, sus columnas valen menos que
    // las de otra al 100%, y eso hay que saberlo ANTES de comparar.
    std::printf("%sCobertura por microarquitectura%s\n", B, R);
    std::printf("%s  Que parte de las instrucciones sabe cronometrar cada una."
                "  Una columna con poca\n  cobertura no es comparable con una "
                "que las cuesta todas.%s\n",
                D, R);
    // El indice es la clave: en la matriz de abajo las columnas se numeran en
    // vez de abreviarse.  Truncar los nombres a siete caracteres hacia que
    // `amd-zen1` .. `amd-zen5` salieran las cinco como `amd-zen`, y dos
    // columnas con el mismo rotulo no se pueden leer.
    std::printf("   %3s %-22s %10s %10s  %s\n", "col", "microarquitectura",
                "instrs", "con coste", "cobertura");
    for (size_t k = 0; k < uarchs.size(); ++k) {
        uint32_t tot = 0, cst = 0;
        for (const auto &f : filas) {
            tot += f.coste[k].instr_count;
            cst += f.coste[k].costed;
        }
        const double pc = tot ? 100.0 * cst / tot : 0.0;
        const char *col = pc >= 99.0 ? VE : (pc >= 80.0 ? AM : RO);
        std::printf("   %s%3zu%s %-22s %10u %10u  %s%5.1f%%%s\n", CI, k + 1, R,
                    instr_db::microarch_name(kIsa, uarchs[k]), tot, cst, col,
                    pc, R);
    }
    std::printf("\n");

    // --- Coste por INSTRUCCION DE LA VM -----------------------------------
    //
    // Una fila por opcode, columnas estrechas.  Antes habia 21 columnas -- una
    // por microarquitectura -- y la linea se iba a 191 caracteres: el terminal
    // la partia en dos y la tabla dejaba de leerse.  Mas filas y menos
    // columnas es mas util que la matriz completa, que ya esta en el JSON.
    //
    // La dispersion entre microarquitecturas NO se pierde: va como min-max con
    // el nombre de las dos que marcan los extremos, que es lo que hace falta
    // para decidir -- si un opcode cuesta 1 ciclo en una CPU y 30 en otra, eso
    // es el dato, no su media.
    // Los extremos se calculan sobre el TOTAL (exec + decode), no sobre el
    // exec: la microarquitectura que minimiza una mitad no tiene por que
    // minimizar la suma, y etiquetar el rango del total con el nombre sacado
    // de una de sus partes seria decir algo que no se comprobo.
    auto extremos = [&](const Opcode *o, float &mn, float &mx, size_t &imn,
                        size_t &imx) {
        mn = 1e30f;
        mx = -1.0f;
        imn = imx = 0;
        for (size_t k = 0; k < uarchs.size(); ++k) {
            const float v = o->ex->coste[k].throughput +
                            (o->de ? o->de->coste[k].throughput : 0.0f);
            if (v < mn) {
                mn = v;
                imn = k;
            }
            if (v > mx) {
                mx = v;
                imx = k;
            }
        }
    };
    auto corto = [&](size_t k) {
        std::string n = instr_db::microarch_name(kIsa, uarchs[k]);
        const size_t g = n.find('-');
        return (g == std::string::npos) ? n : n.substr(g + 1);
    };

    std::printf("%s== Coste por instruccion de la VM: %zu opcodes%s\n", B,
                opcodes.size(), R);
    std::printf("%s   `exec` se paga SIEMPRE; `decode` solo cuando la "
                "instruccion falla en la icache.\n"
                "   El coste real de un sitio es  exec + P_fallo * decode,  y "
                "P_fallo depende de\n"
                "   que PCs conviven en su bucle, no del opcode: por eso van "
                "separados.\n"
                "   Un bloque por opcode, una fila por microarquitectura: "
                "%sla mas barata en verde%s%s,\n   %sla mas cara en rojo%s%s.  "
                "La barra es proporcional al maximo DE ESE opcode.%s\n\n",
                D, VE, D, R, D, RO, D, R);
    // Que es cada columna.  Va una vez y entera; dentro de cada bloque solo
    // se repiten los rotulos.
    std::printf("%s   Las columnas, y de donde sale cada una:\n"
                "     ciclos:exec  ciclos del handler `exec`, cota INFERIOR "
                "del modelo superescalar\n"
                "                  (el maximo entre la presion del puerto mas "
                "cargado y la suma\n"
                "                  de throughput reciproco).  Es lo que "
                "costaria BIEN planificado.\n"
                "     decode       lo mismo para el handler `decode`.\n"
                "     total        exec + decode.\n"
                "     latencia     cota SUPERIOR: la suma en SERIE de las "
                "latencias, o sea sin\n"
                "                  solapar nada.  El coste real esta entre "
                "`total` y `latencia`.\n"
                "     uops         micro-operaciones que emite el conjunto.  "
                "No es tiempo: dice\n"
                "                  cuanto ocupa en el front-end, que es otro "
                "cuello distinto.%s\n",
                D, R);
    // La parte pesada del informe va por el buffer.  Las cabeceras se quedan
    // en `printf` porque son treinta lineas y no compensa: lo que costaba eran
    // las ~5600 del bloque de opcodes.
    Salida out;
    std::vector<const Opcode *> orden;
    for (const auto &o : opcodes)
        orden.push_back(&o);
    std::sort(orden.begin(), orden.end(), [](const Opcode *a, const Opcode *b) {
        const float ca = a->ex ? a->ex->coste[0].throughput : 0.0f;
        const float cb = b->ex ? b->ex->coste[0].throughput : 0.0f;
        return ca < cb;
    });

    // Un BLOQUE por opcode, con una fila por microarquitectura.  Es la unica
    // forma de comparar lo que cuesta el mismo opcode en cada CPU sin una
    // matriz de 21 columnas que el terminal parte por la mitad.
    //
    // El alineado se hace ANTES de colorear: `printf("%-16s")` cuenta los
    // caracteres de escape ANSI como si ocuparan sitio, asi que meter el color
    // dentro del campo descuadra la columna.  Se compone el texto ya padeado
    // y luego se envuelve.
    for (const Opcode *o : orden) {
        float t_mn, t_mx;
        size_t imn, imx;
        extremos(o, t_mn, t_mx, imn, imx);
        Certeza c = o->ex->certeza;
        if (o->de && o->de->certeza > c) c = o->de->certeza;

        out.s(B).izq(o->nombre.c_str(), 18).s(R);
        out.s("  ").s(D).num(o->ex->h.instrs, 0).s(" instr exec").s(R);
        if (o->de)
            out.s(D)
                .s(", decode compartido por ")
                .num(o->de->compartida, 0)
                .s(" opcodes")
                .s(R);
        out.s("  ")
            .s(color_certeza(c))
            .ch('[')
            .s(nombre_certeza(c))
            .ch(']')
            .s(R)
            .nl();

        // Cabecera DENTRO de cada bloque.  Son 232 lineas de mas, pero sin
        // ellas hay que subir hasta el principio del informe para saber que
        // es cada columna -- y con 5600 lineas eso no lo hace nadie.
        // Los rotulos van a la DERECHA, como sus numeros: con `izq` caian
        // desplazados y `ciclos:exec` -- once caracteres en un campo de nueve
        // -- se comia el titulo de la columna siguiente.
        out.s("   ")
            .s(D)
            .izq("microarquitectura", 22)
            .der("exec", 9)
            .der("decode", 9)
            .der("total", 10)
            .der("latencia", 11)
            .der("uops", 8)
            .s("  ciclos / latencia / uops")
            .s(R)
            .nl();

        for (size_t k = 0; k < uarchs.size(); ++k) {
            const auto &ce = o->ex->coste[k];
            const float e = ce.throughput;
            const float d = o->de ? o->de->coste[k].throughput : 0.0f;
            const float t = e + d;
            // Latencia y uops del OPCODE COMPLETO: las dos mitades se suman,
            // igual que los ciclos, porque descodificar y ejecutar ocurren uno
            // detras de otro.
            const float lat =
                ce.latency_sum + (o->de ? o->de->coste[k].latency_sum : 0.0f);
            const uint32_t uops =
                ce.total_uops + (o->de ? o->de->coste[k].total_uops : 0u);
            // Verde el mas barato, rojo el mas caro, y el resto atenuado: sin
            // eso, veintiuna filas de numeros no dicen cual mirar.
            const char *col = (k == imn) ? VE : (k == imx ? RO : D);
            // Barra proporcional al mas caro DEL OPCODE, no del banco entero:
            // lo que interesa aqui es la dispersion dentro de este opcode.
            const int ancho =
                t_mx > 0.0f ? static_cast<int>(24.0f * t / t_mx + 0.5f) : 0;
            out.s("   ")
                .s(col)
                .izq(instr_db::microarch_name(kIsa, uarchs[k]), 22)
                .dec1(e, 9)
                .dec1(d, 9)
                .dec1(t, 10)
                .dec1(lat, 11)
                .num(uops, 8)
                .s("  ")
                .rep('#', ancho > 24 ? 24 : ancho)
                .s(R)
                .nl();
        }

        // --- Resumen del opcode, presentado como tres filas mas -----------
        // Van con el mismo formato que las microarquitecturas para poder
        // compararlas de un vistazo, pero SEPARADAS y con nombre en
        // mayusculas: no son maquinas, son agregados, y una fila que dijera
        // "promedio" mezclada entre las reales se leeria como una CPU mas.
        auto lat_de = [&](size_t k) {
            return o->ex->coste[k].latency_sum +
                   (o->de ? o->de->coste[k].latency_sum : 0.0f);
        };
        auto uops_de = [&](size_t k) {
            return o->ex->coste[k].total_uops +
                   (o->de ? o->de->coste[k].total_uops : 0u);
        };
        float e_sum = 0.0f, d_sum = 0.0f, l_sum = 0.0f;
        double u_sum = 0.0;
        for (size_t k = 0; k < uarchs.size(); ++k) {
            e_sum += o->ex->coste[k].throughput;
            d_sum += o->de ? o->de->coste[k].throughput : 0.0f;
            l_sum += lat_de(k);
            u_sum += uops_de(k);
        }
        const float n = static_cast<float>(uarchs.size());
        const struct {
            const char *nombre;
            float e, d, t, lat;
            double uops;
            const char *col;
        } resumen[] = {
            // MINIMO y MAXIMO se dan en la microarq que minimiza/maximiza el
            // TOTAL, no cada columna por su cuenta: si cada una viniera de una
            // maquina distinta, la fila no describiria ninguna.
            {"MINIMO", o->ex->coste[imn].throughput,
             o->de ? o->de->coste[imn].throughput : 0.0f, t_mn, lat_de(imn),
             static_cast<double>(uops_de(imn)), VE},
            {"MAXIMO", o->ex->coste[imx].throughput,
             o->de ? o->de->coste[imx].throughput : 0.0f, t_mx, lat_de(imx),
             static_cast<double>(uops_de(imx)), RO},
            // La media de los totales es la suma de las medias, asi que las
            // columnas de esta fila siguen sumando entre si.
            {"PROMEDIO", e_sum / n, d_sum / n, (e_sum + d_sum) / n, l_sum / n,
             u_sum / n, CI},
        };
        out.s("   ").s(D).rep('-', 81).s(R).nl();
        for (const auto &r : resumen) {
            const int ancho =
                t_mx > 0.0f ? static_cast<int>(24.0f * r.t / t_mx + 0.5f) : 0;
            out.s("   ")
                .s(B)
                .s(r.col)
                .izq(r.nombre, 22)
                .dec1(r.e, 9)
                .dec1(r.d, 9)
                .dec1(r.t, 10)
                .dec1(r.lat, 11)
                .dec1(r.uops, 8)
                .s("  ")
                .rep('#', ancho > 24 ? 24 : ancho)
                .s(R)
                .nl();
        }
        out.nl();
        // Se vuelca por tramos para no tener el informe entero en memoria si
        // algun dia crece: el buffer se reserva una vez y se reutiliza.
        if (out.b.size() > (4u << 20)) {
            std::fflush(stdout);
            out.volcar(stdout);
        }
    }
    // Antes de volver a `printf`: si no, lo que quede en el buffer saldria
    // DESPUES de la leyenda y el informe se leeria desordenado.
    std::fflush(stdout);
    out.volcar(stdout);
    std::fflush(stdout);

    std::printf("%s`ciclos` es la cota INFERIOR del modelo superescalar; la "
                "SUPERIOR es la suma en\nserie de latencias.  El coste real "
                "esta entre las dos.  %sexacto%s = un bloque, "
                "%sacotado%s = solo\nsaltos hacia adelante, %scota%s = hay "
                "bucle o llamada no seguida.%s\n",
                D, VE, D, AM, D, RO, D, R);

    // --- JSON ------------------------------------------------------------
    // La tabla de arriba es para leerla; esto es para CONSUMIRLA.  El modelo
    // de coste no vive en un terminal: el nivel 3 de Big-O tiene que poder
    // pesar cada opcode sin volver a desensamblar nada, y para eso necesita
    // el dato, no el informe.
    //
    // Se emite el coste de TODAS las microarquitecturas, no una media: cual
    // aplica lo decide quien consume, y promediarlas aqui perderia justo la
    // dispersion que hace falta para elegir.  Y va la cobertura de cada una,
    // porque un coste sacado del 80% de las instrucciones no vale lo mismo
    // que uno sacado del 100%.
    nlohmann::json j;
    j["isa"] = kIsaNombre;
    j["profundidad_llamadas"] = g_profundidad;
    for (uint32_t u : uarchs)
        j["microarquitecturas"].push_back(instr_db::microarch_name(kIsa, u));

    for (const auto &f : filas) {
        nlohmann::json h;
        h["funcion_usada_por"] = f.opcode;
        h["grupo"] = f.grupo;
        h["opcodes_que_la_comparten"] = f.compartida;
        h["instrucciones_maquina"] = f.h.instrs;
        h["certeza"] = nombre_certeza(f.certeza);
        // El porque de la certeza, no solo la etiqueta: quien lea el JSON
        // dentro de un ano tiene que poder saber si la cota venia de un bucle
        // o de una llamada que no se siguio.
        h["saltos_atras"] = f.h.saltos_atras;
        h["saltos_adelante"] = f.h.saltos_adelante;
        h["llamadas"] = f.h.llamadas;
        h["truncado"] = f.h.truncado;
        for (size_t k = 0; k < uarchs.size(); ++k) {
            const auto &c = f.coste[k];
            nlohmann::json cu;
            cu["microarquitectura"] = instr_db::microarch_name(kIsa, uarchs[k]);
            cu["ciclos_cota_inferior"] = c.throughput;
            cu["latencia_cota_superior"] = c.latency_sum;
            cu["uops"] = c.total_uops;
            cu["instrs"] = c.instr_count;
            cu["emparejadas"] = c.matched;
            cu["con_coste"] = c.costed;
            h["coste"].push_back(cu);
        }
        j["handlers"].push_back(h);
    }

    // Y el coste por OPCODE, que es lo que consume el modelo.  Aqui si va la
    // matriz entera -- las 21 microarquitecturas por opcode --: en el terminal
    // no cabia sin partir las lineas, pero un fichero no tiene ese problema y
    // recortarla obligaria a volver a ejecutar esto para ver el resto.
    for (const auto &o : opcodes) {
        nlohmann::json oj;
        oj["opcode"] = o.nombre;
        oj["tabla"] = o.tabla;
        oj["indice"] = o.indice;
        oj["certeza_exec"] = nombre_certeza(o.ex->certeza);
        if (o.de) {
            oj["certeza_decode"] = nombre_certeza(o.de->certeza);
            oj["opcodes_que_comparten_decode"] = o.de->compartida;
        }
        for (size_t k = 0; k < uarchs.size(); ++k) {
            const auto &ce = o.ex->coste[k];
            const bool hay_d = o.de != nullptr;
            const auto *cd = hay_d ? &o.de->coste[k] : nullptr;
            nlohmann::json cu;
            cu["microarquitectura"] = instr_db::microarch_name(kIsa, uarchs[k]);
            // Los tres ejes que publica el terminal, y los dos sumandos por
            // separado en cada uno.  `total` se da hecho por comodidad, pero
            // el que manda para pesar un sitio sigue siendo
            //     exec + P_fallo * decode
            // y `P_fallo` no esta aqui porque no es del opcode.
            cu["exec_ciclos"] = ce.throughput;
            cu["decode_ciclos"] = cd ? cd->throughput : 0.0f;
            cu["total_ciclos"] = ce.throughput + (cd ? cd->throughput : 0.0f);
            cu["exec_latencia"] = ce.latency_sum;
            cu["decode_latencia"] = cd ? cd->latency_sum : 0.0f;
            cu["total_latencia"] =
                ce.latency_sum + (cd ? cd->latency_sum : 0.0f);
            cu["exec_uops"] = ce.total_uops;
            cu["decode_uops"] = cd ? cd->total_uops : 0u;
            cu["total_uops"] = ce.total_uops + (cd ? cd->total_uops : 0u);
            // La cobertura, por microarquitectura y por opcode.  Sin esto, dos
            // numeros de columnas distintas parecen comparables cuando uno
            // salio del 100% de las instrucciones y el otro del 80%.
            cu["instrs"] = ce.instr_count + (cd ? cd->instr_count : 0u);
            cu["emparejadas"] = ce.matched + (cd ? cd->matched : 0u);
            cu["con_coste"] = ce.costed + (cd ? cd->costed : 0u);
            oj["coste"].push_back(cu);
        }
        // Minimo, maximo y promedio.  En el terminal se pintan como tres filas
        // mas para poder compararlas de un vistazo; aqui van en su propio
        // campo y NO en `coste`, porque en el dato una entrada llamada
        // "promedio" con forma de microarquitectura acabaria leyendose como si
        // fuera una CPU.  Ademas se dice CUAL es la mas barata y la mas cara,
        // que es la mitad util del resumen.
        {
            auto tot_ciclos = [&](size_t k) {
                return o.ex->coste[k].throughput +
                       (o.de ? o.de->coste[k].throughput : 0.0f);
            };
            auto tot_lat = [&](size_t k) {
                return o.ex->coste[k].latency_sum +
                       (o.de ? o.de->coste[k].latency_sum : 0.0f);
            };
            auto tot_uops = [&](size_t k) {
                return o.ex->coste[k].total_uops +
                       (o.de ? o.de->coste[k].total_uops : 0u);
            };
            float e_sum = 0.0f, d_sum = 0.0f, l_sum = 0.0f;
            double u_sum = 0.0;
            float mn = 1e30f, mx = -1.0f;
            size_t imn = 0, imx = 0;
            for (size_t k = 0; k < uarchs.size(); ++k) {
                e_sum += o.ex->coste[k].throughput;
                d_sum += o.de ? o.de->coste[k].throughput : 0.0f;
                l_sum += tot_lat(k);
                u_sum += tot_uops(k);
                const float t = tot_ciclos(k);
                if (t < mn) {
                    mn = t;
                    imn = k;
                }
                if (t > mx) {
                    mx = t;
                    imx = k;
                }
            }
            const float n = static_cast<float>(uarchs.size());
            nlohmann::json r;
            // El minimo y el maximo se eligen por CICLOS TOTALES, y latencia y
            // uops se dan de ESA microarquitectura -- no el minimo de cada
            // columna por su lado, que describiria una maquina que no existe.
            r["minimo_en"] = instr_db::microarch_name(kIsa, uarchs[imn]);
            r["minimo_ciclos"] = mn;
            r["minimo_latencia"] = tot_lat(imn);
            r["minimo_uops"] = tot_uops(imn);
            r["maximo_en"] = instr_db::microarch_name(kIsa, uarchs[imx]);
            r["maximo_ciclos"] = mx;
            r["maximo_latencia"] = tot_lat(imx);
            r["maximo_uops"] = tot_uops(imx);
            r["promedio_ciclos"] = (e_sum + d_sum) / n;
            r["promedio_exec_ciclos"] = e_sum / n;
            r["promedio_decode_ciclos"] = d_sum / n;
            r["promedio_latencia"] = l_sum / n;
            r["promedio_uops"] = u_sum / n;
            oj["resumen"] = r;
        }
        j["opcodes"].push_back(oj);
    }

    const std::string ruta = (argc > 3) ? argv[3] : "coste_opcodes.json";
    std::FILE *fp = std::fopen(ruta.c_str(), "wb");
    if (!fp) {
        std::printf("\n%s[aviso]%s no pude escribir %s\n", AM, R, ruta.c_str());
        return 0; // el informe ya salio: no es motivo para fallar
    }
    const std::string txt = j.dump(2);
    std::fwrite(txt.data(), 1, txt.size(), fp);
    std::fclose(fp);
    std::printf("\n%s[ok]%s JSON: %s%s%s  (%zu handlers x %zu "
                "microarquitecturas)\n",
                VE, R, B, ruta.c_str(), R, filas.size(), uarchs.size());
    return 0;
}
