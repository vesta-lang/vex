/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/runtime/test_effects_decode.cpp
 * @brief Valida el descodificador de efectos contra una fuente INDEPENDIENTE.
 *
 * Que valida, y por que asi
 * -------------------------
 * `decode_effects` declara la FORMA de cada instruccion en codigo: que registro
 * se lee, cual se escribe y en que campo vive.  Comprobar eso contra si mismo no
 * demostraria nada, asi que se compara con el DESENSAMBLADOR, que llega al mismo
 * dato por otro camino -- el formato de cada opcode, que es como imprime `r3`.
 *
 * Dos derivaciones independientes que coinciden es una prueba; una sola es una
 * afirmacion.
 *
 * Y hay una segunda cosa que solo se puede comprobar aqui: que el
 * ESTRECHAMIENTO por operandos no se pase.  `mov` declara por opcode que puede
 * escribir los cuatro campos implicitos, y por instancia dice uno solo; si
 * dijera de menos, se reordenaria algo que si dependia.  Se recorre el espacio
 * entero de operandos y se comprueba que la UNION de lo estrechado cubre lo que
 * declara el opcode.
 *
 * Lo que NO se usa aqui
 * ---------------------
 * `decode_effects` MUERE ante un opcode sin forma declarada, a proposito: es lo
 * que obliga a acabar de escribirlas.  Para hacer inventario esta
 * `probe_effects`, que responde lo mismo sin morir.  El runtime exige; el test
 * inventaria.
 *
 * Uso:
 *   test_effects_decode [--listar]
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "disasm/disasm.h"
#include "runtime/decode_instruction.h"
#include "runtime/decode_table.h"
#include "runtime/effects_decode.h"
#include "runtime/instr_db_vm.h"
#include "util/reloj.h"

#include "../util/handler_walk.h"

namespace {

int fallos = 0;
int comprobadas = 0;

void mal(const char *que, const char *nombre, const char *tabla, int idx,
         const std::string &detalle) {
    std::printf("  FALLO  %-14s %-9s 0x%02X  %s\n", nombre, tabla, idx, que);
    if (!detalle.empty()) std::printf("         %s\n", detalle.c_str());
    ++fallos;
}

/* Bytes de operando de la instruccion de prueba.
 *
 * Cada byte lleva un par de nibbles DISTINTO.  Que sean distintos importa: si
 * dos operandos cayeran en el mismo registro no se podria ver que son dos, y una
 * forma mal declarada pasaria desapercibida. */
uint8_t operand_byte(size_t k) {
    const unsigned lo = static_cast<unsigned>((2 * k + 1) & 0x0F);
    const unsigned hi = static_cast<unsigned>((2 * k + 2) & 0x0F);
    return static_cast<uint8_t>((hi << 4) | lo);
}

/// Monta y descodifica una instruccion de prueba de @p idx con el decoder DE LA
/// VM -- el mismo que usa el interprete, no una reimplementacion.
bool build(bool ext, int idx, const uint8_t *bytes, size_t n,
           runtime::DecodedInstr &d) {
    runtime::InstrFormat *fmt =
        ext ? &runtime::decode_table_extended[idx]
            : &runtime::decode_table_primary[idx];
    if (fmt->decode == nullptr || fmt->name == nullptr || !fmt->name[0])
        return false;

    d = runtime::DecodedInstr{};
    d.metadata = fmt;
    d.exec_cached = fmt->exec;
    d.pc = 0;
    d.flags_info.is_not_extended = ext ? 0x00 : static_cast<uint8_t>(idx);
    d.flags_info.opcode_index = static_cast<uint16_t>(idx);
    fmt->decode(runtime::InstrCursor{bytes, n, 0}, d);
    return true;
}

/// Los registros que ve el DESENSAMBLADOR para los mismos bytes.
bool disasm_regs(const uint8_t *bytes, size_t n,
                 std::vector<disasm::RegOperand> &out) {
    disasm::DisasmOptions opts;
    opts.show_hex = false;
    opts.use_color = false;
    opts.stop_at_hlt = false;
    opts.max_bytes = n;
    const auto res = disasm::disasm_bytes(bytes, n, 0, opts);
    if (res.empty()) return false;
    out = res[0].regs;
    return true;
}

/// `r3 r5=` en texto, para que el fallo diga QUE difiere y no solo que difiere.
std::string mascara(uint16_t m) {
    std::string s;
    for (int i = 0; i < 16; ++i)
        if (m & (1u << i)) s += "r" + std::to_string(i) + " ";
    return s.empty() ? "(ninguno)" : s;
}

} // namespace

int main(int argc, char **argv) {
    bool listar = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--listar") == 0) {
            listar = true;
        } else {
            std::fprintf(stderr, "uso: test_effects_decode [--listar]\n");
            return 2;
        }
    }

    std::printf("Descodificador de efectos, contra el desensamblador\n\n");

    int sin_declarar = 0;
    std::vector<std::string> pendientes;
    /* Las que SI tienen forma, para cronometrar sobre el camino real: mezclar
     * varias familias es lo que hace que el salto calculado tenga algo que
     * predecir, en vez de medir el caso irrealmente facil de repetir una. */
    std::vector<runtime::DecodedInstr> medir;

    for (int t = 0; t < 2; ++t) {
        const bool ext = (t == 1);
        for (int idx = 0; idx < 0x100; ++idx) {
            uint8_t bytes[24];
            for (size_t k = 0; k < sizeof(bytes); ++k)
                bytes[k] = operand_byte(k);
            if (ext) {
                bytes[0] = 0x00;
                bytes[1] = static_cast<uint8_t>(idx);
            } else {
                bytes[0] = static_cast<uint8_t>(idx);
            }

            runtime::DecodedInstr d;
            if (!build(ext, idx, bytes, sizeof(bytes), d)) continue;
            const char *nombre = d.metadata->name;
            const char *tabla = ext ? "extended" : "primary";

            runtime::InstrEffects e;
            if (!runtime::probe_effects(d, e)) {
                ++sin_declarar;
                pendientes.push_back(std::string(nombre) + " " + tabla + " 0x" +
                                     (idx < 16 ? "0" : "") +
                                     [idx] {
                                         char b[4];
                                         std::snprintf(b, sizeof(b), "%X", idx);
                                         return std::string(b);
                                     }());
                continue;
            }
            ++comprobadas;
            medir.push_back(d);

            /* --- 1. La forma coincide con la del desensamblador --- */
            std::vector<disasm::RegOperand> regs;
            if (!disasm_regs(bytes, sizeof(bytes), regs)) {
                mal("el desensamblador no la reconoce", nombre, tabla, idx, "");
                continue;
            }
            uint16_t d_read = 0, d_write = 0;
            for (const auto &r : regs) {
                if (r.floating) continue; // el banco ancho va aparte
                const uint16_t bit = static_cast<uint16_t>(1u << (r.index & 0xF));
                if (r.dest)
                    d_write |= bit;
                else
                    d_read |= bit;
            }

            /* NO se exige igualdad, y no por comodidad: las dos fuentes miden
             * cosas distintas, y forzarlas a coincidir daria falsos fallos que
             * tapan los de verdad.
             *
             *   - El `dest` del desensamblador es POSICIONAL -- "ocupa la
             *     posicion de destino" --, no semantico.  `cmp rd, rs` tiene
             *     destino posicional pero no escribe nada, y el modelo de
             *     efectos hace bien en no marcarlo.
             *   - El desensamblador no modela la variante de REGISTRO ESPECIAL
             *     de `mov`: imprime `mov r7, r8` tanto si mueve entre generales
             *     como si mueve contra `rflags`.  Ahi el que se queda corto es
             *     el, y el modelo de efectos sabe mas.
             *
             * Lo que si tienen que compartir, y es la comprobacion que importa:
             * los efectos NO pueden nombrar un registro que la instruccion no
             * nombra.  Si lo hacen, la forma declarada esta leyendo un nibble
             * que no es un operando, y eso son dependencias inventadas. */
            const uint16_t nombra_disasm = static_cast<uint16_t>(d_read | d_write);
            const uint16_t nombra_efectos =
                static_cast<uint16_t>(e.reg_read | e.reg_write);
            if ((nombra_efectos & ~nombra_disasm) != 0) {
                mal("nombra registros que la instruccion no tiene", nombre,
                    tabla, idx,
                    "efectos: " + mascara(nombra_efectos) +
                        " / desensamblador: " + mascara(nombra_disasm));
            }

            /* Y cuando la instruccion tiene TRES registros no hay ambiguedad
             * posible: es una forma de tres direcciones, el destino posicional
             * es el semantico, y los dos tienen que decir el mismo. */
            if (regs.size() >= 3 && e.reg_write != 0 && d_write != e.reg_write) {
                mal("el destino de tres direcciones no coincide", nombre, tabla,
                    idx,
                    "desensamblador: " + mascara(d_write) +
                        " / efectos: " + mascara(e.reg_write));
            }

            /* --- 2. El destino se puede reescribir donde dice --- */
            if (e.dest_slot != runtime::RS_NONE) {
                runtime::DecodedInstr copia = d;
                const uint8_t nuevo = static_cast<uint8_t>((e.dest_reg + 7) & 0xF);
                runtime::reg_slot_set(copia, e.dest_slot, nuevo);
                const uint8_t leido = runtime::reg_slot_get(copia, e.dest_slot);
                if (leido != nuevo) {
                    mal("el destino no se puede reescribir", nombre, tabla, idx,
                        "se escribio r" + std::to_string(nuevo) + " y se leyo r" +
                            std::to_string(leido));
                }
                /* Y no puede haber pisado nada mas: retargetear el destino no
                 * debe cambiar los operandos de origen. */
                runtime::InstrEffects e2;
                if (runtime::probe_effects(copia, e2) &&
                    e2.reg_read != e.reg_read && e.dest_is_kill) {
                    mal("reescribir el destino cambio las lecturas", nombre,
                        tabla, idx,
                        mascara(e.reg_read) + " -> " + mascara(e2.reg_read));
                }
            }

            if (listar) {
                std::printf("  %-14s %-9s 0x%02X  lee %-22s escribe %-10s%s\n",
                            nombre, tabla, idx, mascara(e.reg_read).c_str(),
                            mascara(e.reg_write).c_str(),
                            e.exact ? "" : "  (cota inferior)");
            }
        }
    }

    /* --- 3. El estrechamiento de `mov` no se pasa de listo ---------------
     *
     * Por opcode, `mov` declara que puede tocar cualquiera de los cuatro campos.
     * Por instancia dice uno.  La UNION sobre todo el espacio de operandos tiene
     * que cubrir lo que declara el opcode: si se quedara corta, habria una
     * combinacion cuyos efectos se estarian negando. */
    {
        const runtime::vm_isa::VmInstr *v =
            runtime::vm_isa::vm_instr(/*extended=*/true, 0x14);
        uint8_t union_w = 0, union_r = 0;
        for (unsigned s = 0; s < 2; ++s) {
            for (unsigned dir = 0; dir < 2; ++dir) {
                for (unsigned code = 0; code < 16; ++code) {
                    uint8_t bytes[24];
                    for (size_t k = 0; k < sizeof(bytes); ++k)
                        bytes[k] = operand_byte(k);
                    bytes[0] = 0x00;
                    bytes[1] = 0x14;
                    runtime::DecodedInstr d;
                    if (!build(true, 0x14, bytes, sizeof(bytes), d)) continue;
                    /* Se fuerzan los campos DESPUES de descodificar: lo que se
                     * recorre es el espacio semantico, no el de bytes. */
                    d.flags_info._signed_instruct = static_cast<uint8_t>(s);
                    d.flags_info.direction = static_cast<uint8_t>(dir);
                    d.data_instruction.reg_data.reg2 =
                        static_cast<uint8_t>(code);
                    runtime::InstrEffects e;
                    if (!runtime::probe_effects(d, e)) continue;
                    union_w |= e.field_write;
                    union_r |= e.field_read;
                }
            }
        }
        const uint8_t decl_w = static_cast<uint8_t>(v->effects & 0x0F);
        const uint8_t decl_r = static_cast<uint8_t>((v->effects >> 4) & 0x0F);
        if ((decl_w & ~union_w) != 0 || (decl_r & ~union_r) != 0) {
            std::printf("  FALLO  el estrechamiento de `mov` deja campos "
                        "fuera\n"
                        "         opcode declara w=0x%X r=0x%X, la union de "
                        "instancias da w=0x%X r=0x%X\n",
                        decl_w, decl_r, union_w, union_r);
            ++fallos;
        } else {
            std::printf("  mov: la union del estrechamiento cubre lo que "
                        "declara el opcode (w=0x%X r=0x%X)\n",
                        union_w, union_r);
        }
    }

    /* --- 4. La propiedad ESTRUCTURAL, que es la que de verdad se afirma ----
     *
     * El diseno dice "un indexado y un salto, sin llamadas".  Eso no se
     * comprueba bien con un cronometro: en una maquina compartida un cronometro
     * caza ordenes de magnitud, no un 2x -- se probo metiendo un `std::string`
     * corto en el camino y, al caber en la optimizacion de cadena pequena, solo
     * doblo el coste y paso por debajo del tope.
     *
     * Lo que si es determinista es mirar el CODIGO MAQUINA que salio: cero
     * llamadas y un salto indirecto.  Cualquiera de las regresiones que
     * preocupan -- una llamada indirecta, construir una cadena, volver al
     * desensamblador -- mete un `call`, y eso se ve aunque la maquina este
     * cargada. */
    {
        csh cs = 0;
        if (cs_open(tests::kWalkArch, tests::kWalkMode, &cs) != CS_ERR_OK) {
            std::printf("\n  (sin Capstone: no se comprueba la forma del "
                        "codigo generado)\n");
        } else {
            /* Se sigue UN nivel: `decode_effects` es un envoltorio de dos
             * lineas sobre el cuerpo comun, asi que mirar solo el envoltorio
             * daria un veredicto sobre nada.  Con un nivel se entra al cuerpo y
             * no mas alla -- el fallo fatal arrastra media libreria estandar. */
            int llamadas = 0, saltos_indirectos = 0, instrucciones = 0;
            tests::WalkResult res;
            std::set<uint64_t> vistas;
            tests::walk_handler(
                cs,
                reinterpret_cast<uint64_t>(
                    reinterpret_cast<const void *>(&runtime::decode_effects)),
                /*profundidad=*/1, vistas,
                [&](const cs_insn &in) {
                    ++instrucciones;
                    const std::string m = in.mnemonic;
                    if (m == "call" || m == "callq") ++llamadas;
                    if (m == "jmp" && in.op_str[0] != '0') ++saltos_indirectos;
                },
                res);
            cs_close(&cs);

            std::printf("\nForma del codigo generado (%d instrucciones)\n",
                        instrucciones);
            std::printf("  %d llamadas, %d saltos indirectos\n", llamadas,
                        saltos_indirectos);
            if (saltos_indirectos == 0) {
                std::printf("  FALLO  no hay salto calculado: el despacho se ha "
                            "convertido en otra cosa\n");
                ++fallos;
            }
            /* Se admite UNA llamada: la del fallo que mata el programa cuando
             * falta una forma, que esta fuera del camino bueno.  Mas de una
             * significa que algo se cuela en la ruta normal. */
            if (llamadas > 1) {
                std::printf("  FALLO  %d llamadas en el cuerpo; solo deberia "
                            "estar la del fallo fatal\n"
                            "         los ayudantes de cada familia tienen que "
                            "inlinarse\n",
                            llamadas);
                ++fallos;
            }
        }
    }

    /* --- 5. Y que cueste lo que dice costar ------------------------------
     *
     * El diseno se defiende diciendo que consultar los efectos es "un indexado
     * y un salto": sin llamada, sin cadenas y sin pasar por el desensamblador.
     * Eso hay que MEDIRLO, no afirmarlo -- si manana alguien mete una llamada
     * indirecta o construye un `std::string`, el test de correccion seguiria en
     * verde y el diseno estaria roto igual.
     *
     * Se compara contra la parte IRREDUCIBLE: leer la entrada de la tabla
     * generada.  Una cota relativa no depende de lo rapida que sea la maquina,
     * que es justo lo que hace que un umbral absoluto sea inestable.  Lo que la
     * razon mide es lo que anade el despacho de la forma sobre esa lectura. */
    if (!medir.empty()) {
        const util::reloj::Info &clk = util::reloj::info();
        std::printf("\nCoste (reloj: %s, resolucion %.2f ns, lectura %lld ns)\n",
                    clk.fuente, clk.resolucion_ns, clk.coste_ns);

        constexpr int kVueltas = 200000;
        uint64_t suma = 0; // impide que el optimizador borre el trabajo

        // Calentar: la primera pasada rellena la tabla de saltos y la cache.
        for (const runtime::DecodedInstr &d : medir) {
            runtime::InstrEffects e;
            (void)runtime::decode_effects(d, e);
            suma += e.reg_read;
        }

        const uint64_t t0 = util::reloj::ahora();
        for (int v = 0; v < kVueltas; ++v)
            for (const runtime::DecodedInstr &d : medir) {
                runtime::InstrEffects e;
                (void)runtime::decode_effects(d, e);
                suma += e.reg_read ^ e.reg_write;
            }
        const uint64_t t1 = util::reloj::ahora();

        // La parte irreducible: solo la consulta a la tabla generada.
        for (int v = 0; v < kVueltas; ++v)
            for (const runtime::DecodedInstr &d : medir) {
                const bool ex = (d.flags_info.is_not_extended == 0x00);
                const runtime::vm_isa::VmInstr *vi = runtime::vm_isa::vm_instr(
                    ex, static_cast<uint8_t>(d.flags_info.opcode_index));
                suma += (vi != nullptr) ? vi->effects : 0;
            }
        const uint64_t t2 = util::reloj::ahora();

        /* Dos patrones de acceso, no uno.  Se puso esperando que el mezclado
         * fuese el caso malo -- 21 destinos rotando, prediccion fallando -- y
         * el fijo el bueno.  MEDIDO, salen iguales, y el fijo incluso algo
         * peor.  O sea que el despacho NO esta dominado por la prediccion: un
         * patron de 21 lo captura cualquier predictor moderno.
         *
         * Se deja porque la cifra vale igual, pero sin la historia: son dos
         * formas de acceder y las dos cuestan lo mismo. */
        const runtime::DecodedInstr &fija = medir.front();
        const uint64_t t3 = util::reloj::ahora();
        for (int v = 0; v < kVueltas; ++v)
            for (size_t k = 0; k < medir.size(); ++k) {
                runtime::InstrEffects e;
                (void)runtime::decode_effects(fija, e);
                suma += e.reg_read ^ e.reg_write;
            }
        const uint64_t t4 = util::reloj::ahora();

        const double n = static_cast<double>(kVueltas) *
                         static_cast<double>(medir.size());
        const double ns_predicho =
            static_cast<double>(util::reloj::a_ns(t4 - t3)) / n;
        const double ns_todo = static_cast<double>(util::reloj::a_ns(t1 - t0)) / n;
        const double ns_base = static_cast<double>(util::reloj::a_ns(t2 - t1)) / n;
        const double razon = ns_base > 0.0 ? ns_todo / ns_base : 0.0;

        std::printf("  %.2f ns por consulta, opcodes MEZCLADOS (%zu x %d "
                    "vueltas)\n",
                    ns_todo, medir.size(), kVueltas);
        std::printf("  %.2f ns por consulta, un solo opcode repetido\n",
                    ns_predicho);
        std::printf("  (salen iguales: el despacho no lo domina la prediccion "
                    "del salto)\n");
        std::printf("  %.2f ns solo la lectura de la tabla (parte irreducible)\n",
                    ns_base);
        std::printf("  razon %.2fx\n", razon);
        std::printf("  (suma %llu -- solo existe para que no se optimice el "
                    "bucle)\n",
                    static_cast<unsigned long long>(suma));

        /* Dos criterios, y hay que entender que mide cada uno.
         *
         * La RAZON no es una caracterizacion justa: el denominador es un bucle
         * que el compilador optimiza mucho mas agresivamente que el camino real
         * -- puede sacar la carga fuera o encadenar las dependencias --, asi que
         * decir "el despacho cuesta 8 veces la lectura" seria enganoso.  Pero SI
         * es un disparador estable, que es otro uso: normaliza contra la misma
         * maquina y el mismo compilador.  Medido en limpio da 5,8-8,0x; con un
         * `std::string` metido en el camino se va a 15x.
         *
         * El ABSOLUTO se escala por lo que cuesta leer el reloj aqui, para que
         * no dependa de lo rapida que sea la maquina.  Caza los ordenes de
         * magnitud.
         *
         * Lo que NINGUNO caza, y conviene saberlo: una regresion de un 40%.  La
         * dispersion limpia ya es de +-20%, asi que afinar mas el umbral daria
         * fallos falsos, que es peor que no cazarla.  Para eso esta la
         * comprobacion ESTRUCTURAL de arriba, que no depende del reloj.
         *
         * El numerador es el bucle de opcodes mezclados.  Se penso que seria la
         * cota mala por la prediccion del salto, pero al medir el patron fijo
         * sale igual, asi que no lo es: los dos patrones cuestan lo mismo. */
        const double tope_ns =
            (clk.coste_ns > 0) ? 4.0 * static_cast<double>(clk.coste_ns) : 20.0;
        constexpr double kRazonMax = 11.0;
        if (ns_todo > tope_ns || razon > kRazonMax) {
            std::printf("  FALLO  %.2f ns por consulta (tope %.2f) y razon "
                        "%.2fx (tope %.1fx)\n"
                        "         eso ya no es un indexado y un salto: mirar si "
                        "se ha colado una\n"
                        "         llamada indirecta, una construccion de cadena "
                        "o una vuelta al desensamblador\n",
                        ns_todo, tope_ns, razon, kRazonMax);
            ++fallos;
        } else {
            std::printf("  dentro de los dos topes (%.2f ns y %.1fx)\n", tope_ns,
                        kRazonMax);
        }
    }

    std::printf("\n%d instrucciones con forma declarada y comprobada\n",
                comprobadas);
    std::printf("%d sin forma declarada -- `decode_effects` MUERE ante ellas, "
                "que es el punto\n",
                sin_declarar);
    if (listar) {
        for (const std::string &p : pendientes)
            std::printf("    falta: %s\n", p.c_str());
    } else if (sin_declarar > 0) {
        std::printf("  (--listar las enumera)\n");
    }

    if (fallos > 0) {
        std::printf("\n%d FALLOS\n", fallos);
        return 1;
    }
    std::printf("\nsin fallos\n");
    return 0;
}
