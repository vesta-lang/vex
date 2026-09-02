/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/coste/test_efectos_opcodes.cpp
 * @brief Que registros nombra cada opcode, segun EL DESENSAMBLADOR.
 *
 * Para que
 * --------
 * Sin saber que registros toca cada instruccion no se puede afirmar que dos son
 * independientes, y sin eso no hay ni reordenacion dentro de un paquete ni
 * vectorizacion: las dos cosas que quedan por hacer del plan de la VM.
 *
 * De donde sale el dato
 * ---------------------
 * Del desensamblador, `disasm::DisasmResult::regs`.  No de una tabla escrita a
 * mano, ni ejecutando los manejadores, ni deduciendo el formato: el
 * desensamblador es el unico sitio que YA conocia el formato de los 232 opcodes
 * -- no se puede imprimir `r3` sin saber de que campo sale -- y nadie puede
 * anadir un opcode sin ensenarselo.  Una tabla aparte envejece en silencio, y
 * el fallo que produce es de los malos: se reordenan dos instrucciones que si
 * dependian.
 *
 * Dos intentos anteriores, y por que se tiraron
 * ---------------------------------------------
 *   1. EJECUTAR cada manejador con operandos inventados y mirar que cambia.
 *      El union de operandos tiene ocho interpretaciones de los mismos 16 bytes
 *      -- los mismos ocho primeros son a la vez `reg1/reg2`, la formula
 *      `base+index*scale+disp` y un INMEDIATO de 64 bits -- y no hay ningun
 *      patron de relleno valido para todas a la vez.  Salieron divisiones por
 *      cero, `dlopen("")`, y un opcode que tomo un inmediato inventado por una
 *      longitud y pidio **18 GB en una sola llamada**.
 *   2. DESCODIFICAR dos veces con marcadores distintos y ver que bytes del
 *      union seguian al marcador.  Correcto y sin efectos, pero deducia el
 *      formato en vez de preguntarselo a quien ya lo sabe.
 *
 * Que comprueba
 * -------------
 * Que todo opcode con operandos de registro los declara, y saca la tabla.  Si
 * alguien anade un opcode y no ensena al desensamblador a imprimirlo, sale
 * aqui con "(ninguno)" en vez de colarse en silencio.
 *
 * Uso:
 *   test_efectos_opcodes [--desde N]
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <capstone/capstone.h>

#include "disasm/disasm.h"
#include "runtime/decode_instruction.h"
#include "runtime/decode_table.h"
#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"

#include "runtime/instr_db_vm.h"

#include "../util/opcode_effects.h"
#include "../util/report_out.h"

/* El modelo --la forma y los efectos de cada opcode-- vive en
 * `tests/util/opcode_effects.h` porque lo comparte con el test que mide la
 * independencia dentro de los paquetes.  Aqui solo queda PRESENTARLO. */
using namespace tests;

namespace {

/* ---------------------------------------------------------------------------
 * Informe de EFECTOS
 *
 * El equivalente del de costes, para el otro eje: aquel dice cuanto CUESTA cada
 * instruccion, este que TOCA.  Los dos juntos son lo que decide si dos se
 * pueden juntar y si merece la pena.
 * ------------------------------------------------------------------------- */

/// Familia de una instruccion, para agrupar el informe.  Sale del NOMBRE, que
/// en este juego es sistematico (`str*` cadenas, `gc*` recolector, `f*` coma
/// flotante...), no de una lista escrita aparte que se quedaria vieja.
const char *familia_de(const std::string &n, bool salta) {
    if (salta) return "control";
    if (n.rfind("str", 0) == 0) return "cadenas";
    if (n.rfind("gc", 0) == 0) return "recolector";
    if (n.rfind("mon", 0) == 0) return "sincronizacion";
    if (n.rfind("def", 0) == 0 || n.rfind("find", 0) == 0 ||
        n.rfind("add", 0) == 0)
        return "POO / reflexion";
    if (n.rfind("f", 0) == 0 && n.size() > 1 && n != "free" && n != "fastpop" &&
        n != "fastpush")
        return "coma flotante";
    if (n.rfind("m", 0) == 0 && (n == "mld" || n == "mst" || n == "memcpy" ||
                                 n == "memset" || n == "mvtake"))
        return "memoria";
    if (n == "alloc" || n == "free" || n == "realloc" || n == "malloc")
        return "asignador";
    return "general";
}

/// Cuenta de una fila del informe por familia.
struct Grupo {
    int total = 0, exactos = 0, declarados = 0, estrechan = 0;
    int escribe[4] = {0, 0, 0, 0};
    int lee[4] = {0, 0, 0, 0};
};
/// `r3` / `f0`, con `=` delante si es la posicion de destino.
std::string nombrar(const disasm::RegOperand &r) {
    std::string s;
    if (r.dest) s += "=";
    s += r.floating ? 'f' : 'r';
    s += std::to_string(r.index);
    return s;
}

} // namespace

int main(int argc, char **argv) {
    int desde = 0; ///< indice global: 0..255 primaria, 256..511 extendida
    /* Emitir la tabla como pagina de doc.
     *
     * `doc/VMdoc/SetInstruccionesVM` deberia ser la especificacion del set,
     * pero se quedo atras: 108 instrucciones de la tabla no aparecen en ella.
     * Escribir 108 paginas a mano solo aplaza el problema -- se volverian a
     * quedar viejas.  Lo que NO envejece es una tabla GENERADA del codigo: la
     * prosa de cada instruccion sigue en su pagina, y la cobertura la garantiza
     * esto. */
    bool markdown = false;
    /* Instruccion cuyos efectos hay que JUSTIFICAR.  Un efecto sin la prueba
     * de donde sale no se puede ni creer ni descartar. */
    const char *prueba_de = nullptr;
    /* Volcado crudo para el generador de la base de datos de la VM. */
    bool json_out = false;
    /* Listar los opcodes cuyos efectos NO se saben del todo, con el motivo. */
    bool huecos = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--desde") == 0 && i + 1 < argc) {
            desde = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--markdown") == 0) {
            markdown = true;
        } else if (std::strcmp(argv[i], "--huecos") == 0) {
            huecos = true;
        } else if (std::strcmp(argv[i], "--json") == 0) {
            json_out = true;
        } else if (std::strcmp(argv[i], "--prueba") == 0 && i + 1 < argc) {
            prueba_de = argv[++i];
        } else {
            std::fprintf(stderr, "uso: test_efectos_opcodes [--desde N] "
                                 "[--markdown] [--prueba NOMBRE]\n");
            return 2;
        }
    }

    const std::vector<OpcodeRow> rows = build_opcode_model(desde);


    // --- Volcado en JSON, para el generador de la base de datos ---
    if (json_out) {
        std::printf("{\n  \"opcodes\": [\n");
        for (size_t i = 0; i < rows.size(); ++i) {
            const OpcodeRow &f = rows[i];
            std::printf("    {\"nombre\": \"%s\", \"tabla\": \"%s\", "
                        "\"indice\": %d, \"bytes\": %zu, \"modo\": \"%s\", "
                        "\"salta\": %s, \"implementada\": %s, "
                        "\"exacto\": %s, \"escribe\": %u, \"lee\": %u, "
                        "\"tablas_resueltas\": %u, \"motivo\": \"",
                        f.nombre.c_str(), f.tabla, f.indice, f.bytes,
                        f.modo.c_str(), f.salta ? "true" : "false",
                        f.implementada ? "true" : "false",
                        f.imp.completo ? "true" : "false", f.imp.escribe,
                        f.imp.lee, f.imp.tablas);
            /* POR QUE se quedo corto.  Es la SEMILLA de la declaracion: lo que
             * se declare nace del diagnostico del analisis, no de lo que
             * alguien recuerde del manejador. */
            if (!f.imp.completo && !f.imp.sin_resolver.empty()) {
                const std::string &s = f.imp.sin_resolver[0];
                const size_t nl = s.find('\n');
                const std::string primera = s.substr(0, nl);
                const size_t dp = primera.find(": ");
                std::printf("%s", dp == std::string::npos
                                      ? primera.c_str()
                                      : primera.substr(dp + 2).c_str());
            }
            std::printf("\"");
            std::printf("}%s\n", (i + 1 == rows.size()) ? "" : ",");
        }
        std::printf("  ],\n  \"campos\": [");
        for (size_t k = 0; k < sizeof(kFields) / sizeof(kFields[0]); ++k)
            std::printf("%s\"%s\"", k ? ", " : "", kFields[k].nombre);
        std::printf("]\n}\n");
        return 0;
    }

    /* --- Los huecos: que instrucciones NO se saben del todo, y por que ---
     *
     * En una VM PROPIA no deberia haber ninguna: los efectos de nuestras
     * instrucciones los conocemos.  Cada linea de aqui es trabajo pendiente, y
     * sin el SITIO no es accionable -- dice que no se sabe, no que cerrar. */
    if (huecos) {
        int n = 0;
        for (const OpcodeRow &f : rows) {
            if (f.imp.completo || !f.implementada) continue;
            ++n;
            std::printf("%-16s %-9s 0x%02X  %s\n", f.nombre.c_str(), f.tabla,
                        f.indice, f.salta ? "(salta)" : "");
            if (f.imp.sin_resolver.empty())
                std::printf("    (sin sitio: truncado por tamano)\n");
            for (const auto &s : f.imp.sin_resolver)
                std::printf("    %s\n", s.c_str());
        }
        std::printf("\n%d instrucciones implementadas con efectos INCOMPLETOS "
                    "de %d\n",
                    n, (int)rows.size());
        return 0;
    }
    // --- La prueba de un veredicto concreto ---
    if (prueba_de != nullptr) {
        for (const OpcodeRow &f : rows) {
            if (f.nombre != prueba_de) continue;
            std::printf("%s (%s 0x%02X)%s\n", f.nombre.c_str(), f.tabla,
                        f.indice, f.imp.completo ? "" : "  [COTA INFERIOR]");
            bool alguno = false;
            for (size_t k = 0; k < sizeof(kFields) / sizeof(kFields[0]); ++k) {
                const bool w = (f.imp.escribe >> k) & 1u;
                const bool r = (f.imp.lee >> k) & 1u;
                if (!w && !r) continue;
                alguno = true;
                if (w)
                    std::printf("  %-6s escribe  <- %s\n", kFields[k].nombre,
                                f.imp.prueba_w[k].c_str());
                if (r)
                    std::printf("  %-6s lee      <- %s\n", kFields[k].nombre,
                                f.imp.prueba_r[k].c_str());
            }
            if (!alguno) std::printf("  (ningun efecto implicito)\n");
            if (!f.imp.completo) {
                std::printf("  [COTA INFERIOR] el recorrido se quedo aqui:\n");
                if (f.imp.sin_resolver.empty())
                    std::printf("    (sin sitio: truncado por tamano)\n");
                for (const auto &s : f.imp.sin_resolver)
                    std::printf("    %s\n", s.c_str());
            }
            std::printf("\n");
        }
        return 0;
    }

    // --- Pagina de doc generada ---
    if (markdown) {
        std::printf("# Tabla completa de instrucciones (GENERADA)\n\n");
        std::printf(
            "> No se edita a mano.  Se regenera con:\n>\n"
            "> ```\n> test_efectos_opcodes --markdown > "
            "doc/VMdoc/SetInstruccionesVM/TABLA_GENERADA.md\n> ```\n\n"
            "Sale del codigo: las tablas de `decode_table.cpp` para el "
            "opcode,\n"
            "el modo y el tamano, y el desensamblador para los operandos "
            "--que\n"
            "es quien sabe de que campo sale cada registro--.  Por eso no se\n"
            "puede quedar vieja, que es lo que le paso al resto de paginas: "
            "108\n"
            "instrucciones de la tabla no aparecian en ninguna.\n\n"
            "Las paginas escritas a mano siguen siendo las que explican QUE "
            "hace\n"
            "cada instruccion; esta solo garantiza que ninguna falte.\n\n"
            "En la columna de operandos, `=` marca la posicion de destino.\n"
            "`salta` marca las que transfieren control, que no se reordenan\n"
            "nunca.  `sin impl.` son ranuras con nombre reservado pero sin\n"
            "`exec`/`decode`: la VM las rechaza.\n\n");
        std::printf(
            "La columna de efectos lista lo que la instruccion toca SIN\n"
            "nombrarlo en ningun operando: banderas, pila, marco y contador "
            "de\n"
            "programa.  `=` delante quiere decir que lo escribe.  Sale de\n"
            "analizar el codigo maquina del manejador, y un `?` final avisa "
            "de\n"
            "que queda una llamada indirecta sin seguir: lo listado es "
            "cierto,\n"
            "pero puede haber mas.\n\n");
        std::printf("| instruccion | prefijo | opcode | modo | bytes | "
                    "operandos | efectos | notas |\n");
        std::printf("| :---------- | :-----: | :----: | :--: | :---: | "
                    ":-------- | :------ | :---- |\n");
        for (const OpcodeRow &f : rows) {
            std::string rs;
            for (const auto &r : f.regs)
                rs += nombrar(r) + " ";
            std::string notas;
            if (f.salta) notas += "salta";
            if (!f.implementada)
                notas += notas.empty() ? "sin impl." : ", sin impl.";
            const bool ext = (f.tabla[0] == 'e');
            std::string es;
            for (size_t k = 0; k < sizeof(kFields) / sizeof(kFields[0]); ++k) {
                const bool w = (f.imp.escribe >> k) & 1u;
                const bool r = (f.imp.lee >> k) & 1u;
                if (!w && !r) continue;
                if (w) es += "=";
                es += kFields[k].nombre;
                es += " ";
            }
            if (!f.imp.completo) es += "?";
            std::printf("| `%s` | %s | 0x%02X | %s | %zu | %s | %s | %s |\n",
                        f.nombre.c_str(), ext ? "0x00" : "---", f.indice,
                        f.modo.c_str(), f.bytes,
                        rs.empty() ? "---" : rs.c_str(),
                        es.empty() ? "---" : es.c_str(),
                        notas.empty() ? "" : notas.c_str());
        }
        return 0;
    }

    // --- Informe ---
    int con = 0;
    for (const OpcodeRow &f : rows)
        if (!f.regs.empty()) ++con;

    /* Cuanto alcanza la derivacion de efectos implicitos.
     *
     * Importa decirlo porque NO es completa: un manejador que despacha por
     * puntero de funcion -- toda la familia ALU lo hace, via
     * `nombre_table[mode]` -- esconde detras lo que toca, y ahi el recorrido se
     * queda corto.  Esos salen con `?`, que quiere decir COTA INFERIOR: lo
     * listado es cierto, pero puede haber mas. */
    int limpios = 0, cotas = 0, ciegos = 0, con_flags = 0, con_tabla = 0;
    for (const OpcodeRow &f : rows) {
        const bool algo = (f.imp.escribe | f.imp.lee) != 0;
        if (!algo && f.imp.completo) ++limpios;
        if (!f.imp.completo) ++cotas;
        if (!algo && !f.imp.completo) ++ciegos;
        if (f.imp.escribe & 1u) ++con_flags; // kFields[0] son las flags
        if (f.imp.tablas > 0) ++con_tabla;
    }

    /* Los rangos que se vigilan, impresos.  No es adorno: el criterio es el
     * DESPLAZAMIENTO de un acceso a memoria, asi que si alguno de estos cayera
     * en el rango de los desplazamientos pequenos --los de la pila del propio
     * manejador-- cualquier variable local se contaria como un efecto. Verlos
     * es lo que permite descartar esa confusion en vez de suponerla. */

    // ---- Informe de efectos ---------------------------------------------
    tests::Salida out;
    out.s("Efectos por opcode, derivados del codigo maquina\n");
    out.s("  ISA                : x86-64\n");
    out.s("  profundidad de llamadas: 6\n");
    out.s("  instrucciones      : ").num((uint64_t)rows.size(), 0).s("\n\n");

    /* Los rangos vigilados.  No es adorno: el criterio es el DESPLAZAMIENTO de
     * un acceso a memoria, asi que verlos es lo que permite descartar que un
     * marco de pila corriente se confunda con un campo del proceso. */
    out.s("Campos vigilados dentro de ProcessVM (via offsetof)\n");
    for (size_t k = 0; k < sizeof(kFields) / sizeof(kFields[0]); ++k) {
        char b[64];
        std::snprintf(b, sizeof(b), "  %-8s [0x%02zX, 0x%02zX)\n",
                      kFields[k].nombre, kFields[k].ini, kFields[k].fin);
        out.s(b);
    }

    /* --- Cuanto se SABE ---------------------------------------------------
     *
     * En una VM propia no puede haber instrucciones con efectos desconocidos.
     * Estas tres lineas son el estado de esa promesa. */
    int n_impl = 0, n_exact = 0, n_narrow = 0, n_runtime = 0, n_ranura = 0;
    for (const OpcodeRow &f : rows) {
        if (!f.implementada) { ++n_ranura; continue; }
        ++n_impl;
        const bool ext = (f.tabla[0] == 'e');
        const runtime::vm_isa::VmInstr &v =
            ext ? runtime::vm_isa::kExtended[f.indice & 0xFF]
                : runtime::vm_isa::kPrimary[f.indice & 0xFF];
        if (f.imp.completo) ++n_exact;
        if (v.narrow != runtime::vm_isa::VN_NONE) ++n_narrow;
        if (v.effects & runtime::vm_isa::VE_RUNTIME) ++n_runtime;
    }
    out.s("\nCuanto se sabe\n");
    out.s("  ").num((uint64_t)n_impl, 5).s("  implementadas\n");
    out.s("  ").num((uint64_t)n_exact, 5)
        .s("  EXACTAS       -- el recorrido llego al final\n");
    out.s("  ").num((uint64_t)n_narrow, 5)
        .s("  ESTRECHABLES  -- el efecto sale de un campo del operando, ")
        .s("exacto al formar\n");
    out.s("  ").num((uint64_t)n_runtime, 5)
        .s("  EN EJECUCION  -- el destino solo existe al ejecutar; ")
        .s("guarda y abandono\n");
    out.s("  ").num((uint64_t)n_ranura, 5)
        .s("  ranuras con nombre pero sin implementar\n");

    /* --- Que campo toca cuanta gente --------------------------------------
     *
     * Dice cual de los cuatro es el recurso disputado.  Si casi todas escriben
     * las banderas, las banderas son el cuello de cualquier reordenacion, y eso
     * se ve aqui y no en la tabla de 242 filas. */
    out.s("\nQuien toca cada campo\n");
    out.s("  campo     escriben     leen   ninguno\n");
    for (size_t k = 0; k < sizeof(kFields) / sizeof(kFields[0]); ++k) {
        int w = 0, r = 0;
        for (const OpcodeRow &f : rows) {
            if (!f.implementada) continue;
            if ((f.imp.escribe >> k) & 1u) ++w;
            if ((f.imp.lee >> k) & 1u) ++r;
        }
        char b[80];
        std::snprintf(b, sizeof(b), "  %-8s %8d %8d %9d\n", kFields[k].nombre,
                      w, r, n_impl - w - r + (w && r ? 1 : 0));
        out.s(b);
    }

    /* --- Por FAMILIA ------------------------------------------------------
     *
     * Las 242 filas de golpe no dicen nada.  Agrupadas si: se ve de un vistazo
     * que la aritmetica es exacta entera y que lo que queda por cerrar se
     * concentra en el recolector y la POO, que es donde el despacho es
     * dinamico. */
    std::map<std::string, Grupo> fam;
    for (const OpcodeRow &f : rows) {
        if (!f.implementada) continue;
        Grupo &g = fam[familia_de(f.nombre, f.salta)];
        ++g.total;
        const bool ext = (f.tabla[0] == 'e');
        const runtime::vm_isa::VmInstr &v =
            ext ? runtime::vm_isa::kExtended[f.indice & 0xFF]
                : runtime::vm_isa::kPrimary[f.indice & 0xFF];
        if (f.imp.completo) ++g.exactos;
        if (v.narrow != runtime::vm_isa::VN_NONE) ++g.estrechan;
        if (v.effects & runtime::vm_isa::VE_RUNTIME) ++g.declarados;
        for (int k = 0; k < 4; ++k) {
            if ((f.imp.escribe >> k) & 1u) ++g.escribe[k];
            if ((f.imp.lee >> k) & 1u) ++g.lee[k];
        }
    }
    out.s("\nPor familia\n");
    out.s("  familia            total  exactas  en ejec.  estrechan  ")
        .s("=flags  =pila  =marco  =pc\n");
    for (const auto &kv : fam) {
        const Grupo &g = kv.second;
        char b[160];
        std::snprintf(b, sizeof(b),
                      "  %-18s %5d %8d %9d %10d %7d %6d %7d %4d\n",
                      kv.first.c_str(), g.total, g.exactos, g.declarados,
                      g.estrechan, g.escribe[0], g.escribe[1], g.escribe[2],
                      g.escribe[3]);
        out.s(b);
    }

    /* --- Lo que falta por cerrar, por CAUSA -------------------------------
     *
     * Un analisis que renuncia sin decir por que parece que funciona.  Aqui se
     * dice, y agrupado: las tres causas son la misma cosa --el destino esta en
     * un registro o en una ranura-- y por eso el nivel que las cierra es
     * observar la ejecucion, no seguir puliendo el recorrido estatico. */
    std::map<std::string, int> causas;
    for (const OpcodeRow &f : rows) {
        if (!f.implementada || f.imp.completo) continue;
        std::string c = "sin sitio registrado";
        if (!f.imp.sin_resolver.empty()) {
            const std::string &s = f.imp.sin_resolver[0];
            const size_t dp = s.find(": ");
            const size_t nl = s.find('\n');
            std::string t = s.substr(dp == std::string::npos ? 0 : dp + 2,
                                     nl == std::string::npos ? std::string::npos
                                                             : nl - dp - 2);
            if (t.rfind("jmp q", 0) == 0)
                c = "salto por puntero en memoria";
            else if (t.rfind("jmp", 0) == 0)
                c = "salto por REGISTRO";
            else if (t.rfind("call q", 0) == 0)
                c = "llamada por puntero en memoria";
            else if (t.rfind("call", 0) == 0)
                c = "llamada por REGISTRO";
        }
        ++causas[c];
    }
    if (!causas.empty()) {
        out.s("\nPor que no se cierran solas\n");
        for (const auto &kv : causas) {
            char b[100];
            std::snprintf(b, sizeof(b), "  %5d  %s\n", kv.second,
                          kv.first.c_str());
            out.s(b);
        }
        out.s("  Las tres son lo mismo: el destino solo existe AL EJECUTAR.\n");
    }

    /* --- Reglas de estrechamiento en uso ---------------------------------- */
    bool hay_narrow = false;
    for (const OpcodeRow &f : rows) {
        if (!f.implementada) continue;
        const bool ext = (f.tabla[0] == 'e');
        const runtime::vm_isa::VmInstr &v =
            ext ? runtime::vm_isa::kExtended[f.indice & 0xFF]
                : runtime::vm_isa::kPrimary[f.indice & 0xFF];
        if (v.narrow == runtime::vm_isa::VN_NONE) continue;
        if (!hay_narrow) {
            out.s("\nEstrechables por operando (exacto al formar, sin guarda)\n");
            hay_narrow = true;
        }
        char b[120];
        std::snprintf(b, sizeof(b), "  %-14s %-9s 0x%02X   regla %u\n",
                      f.nombre.c_str(), f.tabla, f.indice, v.narrow);
        out.s(b);
    }
    out.nl();
    out.volcar(stdout);
    /* --- La tabla, instruccion a instruccion ------------------------------
     *
     * Lo de arriba resume; esto es el detalle.  `=` marca lo que se escribe y
     * `?` que el opcode no se cierra solo -- lo cual, con la declaracion, ya no
     * significa "no se sabe" sino "no se sabe TODAVIA". */
    std::printf("%-16s %-9s %6s %6s  %-22s %-24s %s\n", "opcode", "tabla",
                "indice", "salta", "registros", "efectos implicitos", "texto");
    std::printf("%s\n", std::string(120, '-').c_str());
    for (const OpcodeRow &f : rows) {
        std::string rs;
        for (const auto &r : f.regs)
            rs += nombrar(r) + " ";
        /* Los implicitos con la misma notacion que los registros: `=` delante
         * cuando se escribe.  El `?` final avisa de que el manejador tiene
         * llamadas indirectas que no se pudieron seguir, asi que lo que sale
         * es una COTA INFERIOR: puede tocar mas cosas. */
        std::string is;
        for (size_t k = 0; k < sizeof(kFields) / sizeof(kFields[0]); ++k) {
            const bool w = (f.imp.escribe >> k) & 1u;
            const bool r = (f.imp.lee >> k) & 1u;
            if (!w && !r) continue;
            if (w) is += "=";
            is += kFields[k].nombre;
            is += " ";
        }
        if (!f.imp.completo) is += "?";
        std::printf("%-16s %-9s %6d %6s  %-22s %-24s %s\n", f.nombre.c_str(),
                    f.tabla, f.indice, f.salta ? "si" : "-",
                    rs.empty() ? "(ninguno)" : rs.c_str(),
                    is.empty() ? "-" : is.c_str(), f.operandos.c_str());
    }

    /* --- La DB generada sigue coincidiendo con el codigo? ---
     *
     * `src/runtime/instr_db_vm_gen.cpp` es una tabla APARTE, y una tabla aparte
     * envejece: el dia que alguien toque un manejador y no la regenere, la VM
     * reordenaria con efectos que ya no son ciertos.  Eso no da un error, da
     * OTRO RESULTADO.
     *
     * Por eso el derivador la COMPRUEBA en cada ejecucion.  Es lo que permite
     * que la tabla exista: generada mas verificada no se puede desincronizar,
     * mientras que generada a secas si. */
    int discrepan = 0;
    for (const OpcodeRow &f : rows) {
        const bool ext = (f.tabla[0] == 'e');
        const runtime::vm_isa::VmInstr &v =
            ext ? runtime::vm_isa::kExtended[f.indice & 0xFF]
                : runtime::vm_isa::kPrimary[f.indice & 0xFF];
        uint16_t esperado = (f.imp.escribe & 0xF) | ((f.imp.lee & 0xF) << 4);
        if (f.imp.completo && f.implementada)
            esperado |= runtime::vm_isa::VE_EXACT;
        if (f.salta) esperado |= runtime::vm_isa::VE_CONTROL;
        if (f.modo != "REG" && f.modo != "INMED" && f.modo != "NONE")
            esperado |= runtime::vm_isa::VE_MEMORY;
        if (f.implementada) esperado |= runtime::vm_isa::VE_IMPL;

        /* El criterio ya no es "identico" sino "no se queda CORTO".
         *
         * La tabla puede saber MAS que el derivador: las declaraciones anaden
         * lo que el recorrido no alcanza (`VE_RUNTIME`) y pueden ampliar los
         * campos afectados.  Lo que NO puede es saber MENOS: un efecto que el
         * derivador ve y la tabla no declara es exactamente el fallo silencioso
         * -- se reordenarian instrucciones que si dependian --.
         *
         * Asi que los cuatro campos se comprueban por INCLUSION, y las marcas
         * estructurales (implementada, control, memoria, exacto) por igualdad,
         * porque esas no las decide nadie mas que el derivador. */
        const uint16_t campos_der = static_cast<uint16_t>(esperado & 0x00FF);
        const uint16_t campos_tab =
            static_cast<uint16_t>((v.name ? v.effects : 0) & 0x00FF);
        const uint16_t marcas_der = static_cast<uint16_t>(esperado & 0x0F00);
        const uint16_t marcas_tab =
            static_cast<uint16_t>((v.name ? v.effects : 0) & 0x0F00);
        const bool corta = (campos_der & ~campos_tab) != 0;

        if (v.name == nullptr || f.nombre != v.name || corta ||
            marcas_der != marcas_tab) {
            if (discrepan == 0)
                std::printf("\nLA BASE DE DATOS GENERADA NO CUADRA CON EL "
                            "CODIGO:\n");
            std::printf("  %-16s %s 0x%02X: tabla=0x%04X derivado=0x%04X\n",
                        f.nombre.c_str(), f.tabla, f.indice,
                        v.name ? v.effects : 0, esperado);
            ++discrepan;
        }
    }
    if (discrepan > 0) {
        std::printf("\n%d instrucciones difieren.  Regenerar con:\n"
                    "  test_efectos_opcodes --json > efectos.json\n"
                    "  python tools/import/gen_instr_db_vm.py efectos.json "
                    "coste_opcodes.json\n",
                    discrepan);
        return 1;
    }
    std::printf("\nLa base de datos generada cuadra con el codigo (%d "
                "instrucciones).\n",
                (int)rows.size());
    return 0;
}
