/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/coste/test_icache_conflictos.cpp
 * @brief ¿Se pisan entre si las instrucciones de un bucle en la icache?
 *        SUPERADO por @c test_icache_real.  Se conserva como registro.
 *
 * SUS RESULTADOS NO VALEN
 * -----------------------
 * Este test da mal el ORDEN.  Marcaba `tight_loop` entre los peores y, medido
 * ejecutando, `tight_loop` no falla NI UNA VEZ.  El fallo no es un despiste en
 * la simulacion: es que la pregunta no se puede contestar sin ejecutar.
 *
 * Mirando el bytecode quieto se puede saber que instrucciones caen en el mismo
 * conjunto, pero no CUANTAS VECES se ejecuta cada bucle -- ni si se ejecuta.
 * Un bucle que se pisa entero y da dos vueltas sale aqui igual de rojo que el
 * bucle caliente que da veinte millones, y el segundo es el unico que cuesta
 * tiempo.  Ponderar por frecuencia es justo lo que un analisis estatico no
 * tiene.
 *
 * Tampoco distinguia entre lo que ejecuta el INTERPRETE y lo que se va al JIT.
 * La icache es del interprete: lo que `callvm` despacha a codigo compilado no
 * pasa por ella, y aqui todo el bytecode contaba por igual.
 *
 * QUE USAR
 * --------
 * @c test_icache_real, que carga el `.velb`, lo ejecuta sobre un `ProcessVM`
 * de verdad y pregunta a la misma @c icache_lookup que usa el scheduler.  Sus
 * numeros son medidos, con la frecuencia real de cada PC, y con el JIT
 * apagado para que el interprete sea quien ejecuta.
 *
 * POR QUE SIGUE AQUI
 * ------------------
 * No estorba a nadie: es un ejecutable de test aparte, no entra en el
 * compilador ni en la VM.  Y deja constancia de un error que es facil repetir
 * -- contar conflictos posibles y llamarlo coste --, con al lado la medida que
 * lo desmiente.  Borrarlo dejaria la conclusion sin el camino que llevo a
 * ella.
 *
 * La pregunta que se hacia
 * ------------------------
 * La icache de instrucciones descodificadas es de mapeo DIRECTO, 1024 entradas
 * indexadas por `pc & 1023` sobre la direccion en BYTES.  Un fallo obliga a
 * redescodificar, y el modelo de coste dice que descodificar cuesta entre 15 y
 * 25 veces mas que ejecutar.
 *
 * Pero eso solo importa si los fallos se REPITEN.  Con mapeo directo, dos PCs
 * cualesquiera dentro de una ventana de 1024 bytes caen en ranuras distintas:
 * un bucle de menos de 1 KB de bytecode no tiene ni un conflicto y su decode se
 * paga una vez.  El coste del decode solo se sufre si el cuerpo del bucle pasa
 * de ese KB -- y entonces se paga en CADA vuelta.
 *
 * Esa era la idea: contestar si pasa de verdad, y cuanto ganaria cada
 * alternativa.  Contesta lo primero -- si hay bucles que se pisan -- pero no
 * lo segundo, porque para eso hace falta saber cuanto se ejecuta cada uno.
 *
 * Como
 * ----
 * Estatico, sobre el `.velb`: no ejecuta nada y no toca la VM.  Desensambla con
 * el desensamblador del proyecto, busca los saltos hacia ATRAS -- que son los
 * bucles -- y simula la icache sobre cada cuerpo.
 *
 * El modelo de fallos, y por que es este:  en regimen estacionario, si una
 * ranura la comparten K instrucciones del cuerpo y las K se ejecutan en cada
 * vuelta, cada una desaloja a la anterior y las K fallan SIEMPRE.  Una ranura
 * con una sola instruccion acierta siempre despues de la primera vuelta.  Con
 * N vias, una ranura con K <= N tampoco falla.
 *
 * Es una cota OPTIMISTA: supone que todas las instrucciones del cuerpo se
 * ejecutan en cada vuelta.  Un cuerpo con ramas ejecuta menos, asi que los
 * conflictos reales pueden ser menores.  Se dice, no se esconde.
 *
 * Y ahi estaba el agujero, visto en retrospectiva: la salvedad se escribio
 * pensando en un margen de error, cuando en realidad es lo que decide el
 * resultado entero.  Entre "todas las instrucciones se ejecutan siempre" y lo
 * que hace un programa de verdad no hay un margen: hay un orden distinto.
 */

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "disasm/disasm.h"
#include "util/ansi.h"

namespace {

/// Una configuracion de icache a comparar.
struct Config {
    const char *nombre;
    uint32_t entradas;
    uint32_t vias;
    bool hash; ///< true = mezcla bits altos en vez de mascara pelada.

    uint32_t indice(uint64_t pc) const {
        const uint32_t conjuntos = entradas / vias;
        const uint64_t v = hash ? (pc ^ (pc >> 10)) : pc;
        return static_cast<uint32_t>(v & (conjuntos - 1));
    }
    /// Bytes que ocupa.  `DecodedInstr` son 64 bytes exactos -- una linea de
    /// cache --, asi que esto dice si la tabla cabe en la L1 del host.  Una
    /// icache de 64 KB en una L1 de 32 KB convierte cada acierto en un fallo
    /// del nivel de abajo, que es un coste que no se ve en ningun contador.
    uint32_t kib() const { return entradas * 64 / 1024; }
};

/// Un bucle: el tramo entre el destino del salto hacia atras y el propio salto.
struct Bucle {
    uint64_t inicio, fin;
    std::vector<uint64_t> pcs;
    size_t bytes() const { return static_cast<size_t>(fin - inicio); }
};

/// El ultimo `0x...` de los operandos, que es el destino del salto.
/// Formato real: "jge 0x0000000000000063", "r6, r3, jge 0x00000075".
bool destino_de(const std::string &ops, uint64_t &out) {
    const size_t p = ops.rfind("0x");
    if (p == std::string::npos) return false;
    out = std::strtoull(ops.c_str() + p + 2, nullptr, 16);
    return true;
}

bool es_salto(const std::string &m) {
    return m == "jmp" || m == "cmpjmp" || m.compare(0, 2, "je") == 0 ||
           m.compare(0, 2, "jn") == 0 || m.compare(0, 1, "j") == 0;
}

/// Fallos por vuelta en regimen estacionario (ver la cabecera del fichero).
uint32_t fallos(const Config &c, const std::vector<uint64_t> &pcs) {
    std::map<uint32_t, uint32_t> por_conjunto;
    for (uint64_t pc : pcs)
        por_conjunto[c.indice(pc)]++;
    uint32_t n = 0;
    for (const auto &kv : por_conjunto)
        if (kv.second > c.vias) n += kv.second;
    return n;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        std::printf("uso: %s <fichero.velb> [mas.velb ...]\n", argv[0]);
        return 1;
    }
    const char *R = ansi::c(ansi::RESET), *B = ansi::c(ansi::BOLD);
    const char *D = ansi::c(ansi::DIM), *VE = ansi::c(ansi::GREEN);
    const char *AM = ansi::c(ansi::YELLOW), *RO = ansi::c(ansi::RED);

    // La actual va primera: todo lo demas se compara contra ella.
    const Config configs[] = {
        {"actual (1024, directa)", 1024, 1, false},
        {"1024 con hash", 1024, 1, true},
        {"1024, 2 vias", 1024, 2, false},
        {"512 (cabe en L1)", 512, 1, false},
        {"512, 2 vias", 512, 2, false},
        {"2048 (no cabe en L1)", 2048, 1, false},
    };
    const size_t n_cfg = sizeof(configs) / sizeof(configs[0]);

    std::printf("%sConflictos de icache, simulados sobre el bytecode%s\n", B,
                R);
    std::printf("%s  Estatico: no ejecuta nada.  Un bucle de menos de 1 KB de "
                "bytecode no tiene\n  conflictos con la icache actual; el "
                "problema empieza al pasar de ahi.%s\n\n",
                D, R);

    uint64_t tot_bucles = 0, tot_con_conflicto = 0;
    std::vector<uint64_t> suma(n_cfg, 0);

    for (int a = 1; a < argc; ++a) {
        std::FILE *fp = std::fopen(argv[a], "rb");
        if (!fp) {
            std::printf("%s[aviso]%s no pude abrir %s\n", AM, R, argv[a]);
            continue;
        }
        std::fseek(fp, 0, SEEK_END);
        const long n = std::ftell(fp);
        std::fseek(fp, 0, SEEK_SET);
        std::vector<uint8_t> datos(static_cast<size_t>(n < 0 ? 0 : n));
        if (!datos.empty() &&
            std::fread(datos.data(), 1, datos.size(), fp) != datos.size()) {
            std::fclose(fp);
            continue;
        }
        std::fclose(fp);

        disasm::DisasmOptions opts;
        opts.max_bytes = datos.size();
        const auto instrs =
            disasm::disasm_bytes(datos.data(), datos.size(), 0, opts);
        if (instrs.empty()) continue;

        // Saltos hacia ATRAS = bucles.  El cuerpo va del destino al salto.
        std::vector<Bucle> bucles;
        for (const auto &in : instrs) {
            if (!es_salto(in.mnemonic)) continue;
            uint64_t dst = 0;
            if (!destino_de(in.operands, dst)) continue;
            if (dst > in.address) continue; // hacia adelante: no es bucle
            Bucle b;
            b.inicio = dst;
            b.fin = in.address;
            for (const auto &x : instrs)
                if (x.address >= dst && x.address <= in.address)
                    b.pcs.push_back(x.address);
            if (b.pcs.size() > 1) bucles.push_back(std::move(b));
        }
        if (bucles.empty()) continue;

        // Solo se detalla el bucle mas grande de cada fichero: es el unico que
        // puede tener conflictos, y listarlos todos ahoga el informe.
        std::sort(bucles.begin(), bucles.end(),
                  [](const Bucle &x, const Bucle &y) {
                      return x.bytes() > y.bytes();
                  });
        const Bucle &mayor = bucles.front();
        const uint32_t base = fallos(configs[0], mayor.pcs);

        const char *nom = std::strrchr(argv[a], '/');
        const char *nom2 = std::strrchr(argv[a], '\\');
        if (nom2 > nom) nom = nom2;
        nom = nom ? nom + 1 : argv[a];

        std::printf("%s%-28s%s %zu bucles, el mayor: %zu instrs en %zu bytes",
                    B, nom, R, bucles.size(), mayor.pcs.size(), mayor.bytes());
        if (mayor.bytes() >= 1024) std::printf("  %s(pasa de 1 KB)%s", RO, R);
        std::printf("\n");

        for (size_t c = 0; c < n_cfg; ++c) {
            const uint32_t f = fallos(configs[c], mayor.pcs);
            suma[c] += f;
            const double pc =
                mayor.pcs.empty()
                    ? 0.0
                    : 100.0 * f / static_cast<double>(mayor.pcs.size());
            const char *col = f == 0 ? VE : (f < base ? AM : (c ? RO : D));
            std::printf("   %s%-24s%s %4u KB  %s%5u fallos/vuelta (%4.1f%%)%s",
                        D, configs[c].nombre, R, configs[c].kib(), col, f, pc,
                        R);
            if (c && base)
                std::printf("  %s%+.0f%%%s", f < base ? VE : RO,
                            100.0 * (double)f / base - 100.0, R);
            std::printf("\n");
        }
        std::printf("\n");
        ++tot_bucles;
        if (base) ++tot_con_conflicto;
    }

    if (!tot_bucles) {
        std::printf("%sNo se detecto ningun bucle.%s  Sin saltos hacia atras "
                    "no hay nada que simular:\nel decode se paga una vez por "
                    "sitio y se amortiza.\n",
                    AM, R);
        return 0;
    }

    std::printf("%s== Resumen%s\n", B, R);
    std::printf("   ficheros con bucle: %llu   con conflictos: %s%llu%s\n",
                (unsigned long long)tot_bucles, tot_con_conflicto ? RO : VE,
                (unsigned long long)tot_con_conflicto, R);
    if (!tot_con_conflicto) {
        std::printf(
            "%s   Ningun bucle se pisa a si mismo en la icache actual: "
            "el coste del decode se\n   amortiza y cambiar el indice no "
            "ganaria nada.  Es el resultado que hay que\n   tener antes "
            "de tocar el bucle de despacho.%s\n",
            VE, R);
    } else {
        std::printf("   fallos/vuelta sumados, por configuracion:\n");
        for (size_t c = 0; c < n_cfg; ++c)
            std::printf("     %s%-24s%s %llu%s\n", c == 0 ? B : D,
                        configs[c].nombre, R, (unsigned long long)suma[c],
                        c && suma[c] < suma[0] ? "  <- mejor" : "");
        std::printf("%s   Ojo con el KB: `DecodedInstr` son 64 bytes, asi que "
                    "1024 entradas son 64 KB\n   y no caben en una L1 de 32.  "
                    "Una configuracion con menos fallos pero que se\n   salga "
                    "de L1 puede acabar siendo mas lenta: esto cuenta "
                    "conflictos, no tiempo.%s\n",
                    AM, R);
    }
    return 0;
}
