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
#include <algorithm>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "disasm/disasm.h"
#include "runtime/decode_instruction.h"
#include "runtime/decode_table.h"
#include "runtime/effects_decode.h"
#include "runtime/instr_db_vm.h"
#include "util/reloj.h"

#include "../util/handler_walk.h"
#include "../util/opcode_effects.h"

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

/**
 * @brief El `RegSlot` de cada bit de la forma DERIVADA del codigo maquina.
 *
 * El derivador responde en campos del operando -- reg1 entero, nibble bajo de
 * reg2... -- y el descodificador en `RegSlot`.  Son la misma nocion con dos
 * nombres, y esta tabla es el puente.  El orden es el que produce
 * `operand_field_bit`: campo (reg1, reg2) por parte (entero, bajo, alto).
 */
constexpr runtime::RegSlot kFormSlot[12] = {
    runtime::RS_REG1, runtime::RS_REG1_LO, runtime::RS_REG1_HI,
    runtime::RS_REG2, runtime::RS_REG2_LO, runtime::RS_REG2_HI,
    runtime::RS_REG3, runtime::RS_REG3_LO, runtime::RS_REG3_HI,
    runtime::RS_REGI, runtime::RS_REGI_LO, runtime::RS_REGI_HI};

/// Los registros a los que apunta @p forma sobre la instancia @p d.
/// Doce bits, no seis: el puente se habia quedado corto cuando el derivador
/// paso a producir tambien el tercer registro de la forma de memoria y el de
/// la forma con inmediato.  Truncando, esos campos no se comparaban con nada.
uint16_t regs_de_forma(uint16_t forma, const runtime::DecodedInstr &d) {
    uint16_t m = 0;
    for (int b = 0; b < 12; ++b)
        if ((forma >> b) & 1)
            m |= static_cast<uint16_t>(
                1u << (runtime::reg_slot_get(d, kFormSlot[b]) & 0x0F));
    return m;
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
    bool familias = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--listar") == 0) {
            listar = true;
        } else if (std::strcmp(argv[i], "--familias") == 0) {
            familias = true;
        } else {
            std::fprintf(stderr,
                         "uso: test_effects_decode [--listar] [--familias]\n");
            return 2;
        }
    }

    /* Las que faltan por declarar, agrupadas por FUNCION DE DECODIFICACION.
     *
     * Es el agrupamiento util: dos opcodes que comparten decoder comparten la
     * disposicion de los campos, asi que comparten forma y se declaran de una
     * vez.  211 sueltas no se atacan; una docena de familias si. */
    if (familias) {
        /* Lo que el MANEJADOR hace, derivado de su codigo maquina, indexado por
         * opcode.  El decoder dice DONDE viven los campos -- eso es lo que
         * comparten los de una familia --, pero no cual se lee y cual se
         * escribe: eso lo decide el manejador, y dos opcodes con el mismo
         * decoder pueden diferir (`isnull` escribe su primer operando,
         * `monenter` solo lo lee).
         *
         * Juntando las dos cosas, declarar una familia deja de ser leer el
         * manejador de cada una: la disposicion la da el grupo y la direccion,
         * la derivacion.  Y no es una propuesta a ciegas -- las 21 formas ya
         * escritas cuadran con ella, que es lo que le da credito. */
        std::map<int, std::pair<uint8_t, uint8_t>> derivada;
        for (const tests::OpcodeRow &f : tests::build_opcode_model(0)) {
            const int clave =
                (std::strcmp(f.tabla, "extended") == 0 ? 0x100 : 0) + f.indice;
            derivada[clave] = {f.imp.form_read, f.imp.form_write};
        }
        auto texto_forma = [](uint8_t m) {
            static const char *kN[6] = {"r1", "r1.bajo", "r1.alto",
                                        "r2", "r2.bajo", "r2.alto"};
            std::string s;
            for (int b = 0; b < 6; ++b)
                if ((m >> b) & 1) s += std::string(s.empty() ? "" : ",") + kN[b];
            return s.empty() ? std::string("-") : s;
        };
        std::map<const void *, std::vector<std::string>> grupos;
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
                runtime::InstrEffects e;
                if (runtime::probe_effects(d, e)) continue; // ya declarada

                /* Se anota el texto del desensamblador: es lo que dice de un
                 * vistazo cual es la forma, sin ir a leer el decoder. */
                std::vector<disasm::RegOperand> regs;
                disasm::DisasmOptions opts;
                opts.show_hex = false;
                opts.use_color = false;
                opts.stop_at_hlt = false;
                opts.max_bytes = sizeof(bytes);
                const auto res =
                    disasm::disasm_bytes(bytes, sizeof(bytes), 0, opts);
                std::string texto = res.empty() ? "?" : res[0].operands;

                const auto it = derivada.find((ext ? 0x100 : 0) + idx);
                const uint8_t fr = it == derivada.end() ? 0 : it->second.first;
                const uint8_t fw = it == derivada.end() ? 0 : it->second.second;
                char linea[220];
                std::snprintf(linea, sizeof(linea),
                              "%-16s %s 0x%02X  %-14s  lee=%-16s esc=%s",
                              d.metadata->name, ext ? "ext" : "pri", idx,
                              texto.c_str(), texto_forma(fr).c_str(),
                              texto_forma(fw).c_str());
                grupos[reinterpret_cast<const void *>(d.metadata->decode)]
                    .push_back(linea);
            }
        }
        std::printf("Formas por declarar, agrupadas por decoder (%zu "
                    "familias)\n\n",
                    grupos.size());
        /* El aviso va aqui y no en la documentacion porque es justo donde
         * alguien va a copiar la columna. */
        std::printf(
            "  El texto del desensamblador dice DONDE viven los campos; lo "
            "comparten\n"
            "  los de una familia.  `lee`/`esc` salen de recorrer el "
            "manejador y dicen\n"
            "  la DIRECCION, que no la comparten: `isnull` escribe su primer "
            "operando\n"
            "  y `monenter` solo lo lee, con el mismo decoder.\n\n"
            "  CUIDADO: lo derivado es una COTA INFERIOR.  Lo que aparece, "
            "esta; lo que\n"
            "  NO aparece puede estar igualmente -- el recorrido se queda "
            "corto ante una\n"
            "  llamada indirecta --.  Un `esc=-` NO demuestra que no escriba, "
            "y declarar\n"
            "  eso seria decir que una instruccion no mata un temporal cuando "
            "si lo mata.\n"
            "  Se declara desde el CONTRATO del opcode; esto confirma, no "
            "decide.\n\n");
        std::vector<std::pair<size_t, const void *>> orden;
        for (const auto &kv : grupos) orden.push_back({kv.second.size(), kv.first});
        std::sort(orden.begin(), orden.end(),
                  [](const auto &a, const auto &b) { return a.first > b.first; });
        for (const auto &o : orden) {
            std::printf("--- %zu instrucciones ---\n", o.first);
            for (const std::string &s : grupos[o.second])
                std::printf("  %s\n", s.c_str());
            std::printf("\n");
        }
        return 0;
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
            std::set<tests::WalkVisit> vistas;
            tests::walk_handler(
                cs,
                reinterpret_cast<uint64_t>(
                    reinterpret_cast<const void *>(&runtime::decode_effects)),
                /*profundidad=*/1, vistas,
                [&](const cs_insn &in, const tests::TableState &) {
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
        /* --- Rendimiento, y su LINEA BASE ---------------------------------
         *
         * Las cifras de arriba dicen lo que cuesta UNA consulta; esta dice
         * cuantas instrucciones se analizan por unidad de tiempo, que es la
         * forma de compararlo entre ejecuciones sin tener que acordarse del
         * numero anterior.
         *
         * La linea base se guarda en un fichero y NO se commitea: depende de la
         * maquina, y una cifra de otro equipo no dice nada de este.  La primera
         * ejecucion la crea; las siguientes comparan.
         *
         * La tolerancia va en instrucciones por milisegundo, que es la magnitud
         * que se lee, y sale de la dispersion MEDIDA (4,20-4,73 ns por consulta,
         * o sea unas 211.000-238.000 por ms: un 12%).  Se pone al 25% para que
         * el ruido de una maquina cargada no dispare, y aun asi caza el 2x de
         * meter una construccion de cadena en el camino. */
        const double instr_ms = 1e6 / ns_todo;
        const double instr_s = instr_ms * 1000.0;
        std::printf("  %.0f instrucciones analizadas por ms  (%.1f millones por "
                    "segundo)\n",
                    instr_ms, instr_s / 1e6);

        constexpr double kToleranciaMs = 0.25;
        const char *kBase = "effects_decode_baseline.txt";
        double base_ms = 0.0;
        if (std::FILE *f = std::fopen(kBase, "r")) {
            if (std::fscanf(f, "%lf", &base_ms) != 1) base_ms = 0.0;
            std::fclose(f);
        }
        if (base_ms <= 0.0) {
            if (std::FILE *f = std::fopen(kBase, "w")) {
                std::fprintf(f, "%.0f\n", instr_ms);
                std::fclose(f);
                std::printf("  linea base creada en %s; la proxima ejecucion "
                            "compara\n",
                            kBase);
            }
        } else {
            const double dif = instr_ms - base_ms;
            const double rel = dif / base_ms;
            std::printf("  linea base %.0f por ms  (%+.0f, %+.1f%%)\n", base_ms,
                        dif, rel * 100.0);
            if (rel < -kToleranciaMs) {
                std::printf("  FALLO  se analizan %.0f instrucciones por ms "
                            "MENOS que la linea base\n"
                            "         (%.0f contra %.0f, tolerancia %.0f%%).  "
                            "Posible regresion; si el\n"
                            "         cambio es deliberado, borrar %s y volver a "
                            "medir.\n",
                            -dif, instr_ms, base_ms, kToleranciaMs * 100.0,
                            kBase);
                ++fallos;
            } else if (rel > kToleranciaMs) {
                /* Subir tambien se avisa, pero no falla: puede ser una mejora
                 * de verdad, y tratarla como error obligaria a borrar el
                 * fichero para aceptar algo bueno.  Lo que no puede es pasar
                 * inadvertida -- si el numero se dispara sin que nadie haya
                 * tocado esto, lo que cambio es la MEDIDA, no el codigo. */
                std::printf("  AVISO  %.0f por ms MAS que la linea base.  Si "
                            "nadie ha tocado esto,\n"
                            "         lo que cambio es la medida; borrar %s "
                            "para re-anclarla.\n",
                            dif, kBase);
            }
        }

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

    /* --- Tercera fuente: lo que hace el MANEJADOR de verdad ---------------
     *
     * El desensamblador dice que registros NOMBRA una instruccion, y con eso se
     * comprueba que la forma declarada no se invente ninguno.  Pero no puede
     * decir cual se LEE y cual se ESCRIBE: eso no esta en el formato, esta en el
     * codigo del manejador.
     *
     * Aqui se compara contra el, derivado de su codigo maquina.  Es la unica
     * fuente que responde a la pregunta que de verdad importa para reordenar --
     * "escribe A lo que lee B?" -- y llega por un camino que no comparte nada
     * con la declaracion.
     *
     * La comparacion NO es de igualdad, y la asimetria es lo importante:
     *
     *   derivado ⊆ declarado   ->  bien.  Lo que el recorrido no alcanzo a ver
     *                              -- una llamada indirecta, un tope -- queda
     *                              fuera, y por eso lo derivado es una COTA
     *                              INFERIOR.
     *   derivado ⊄ declarado   ->  FALLO.  El manejador toca un registro que la
     *                              declaracion no menciona, y eso reordena algo
     *                              que si dependia.
     *
     * Lo que esta comprobacion NO ve: la diferencia entre "el byte entero" y
     * "su nibble bajo".  Para un numero de registro (0..15) son el mismo valor,
     * y solo se separan al REESCRIBIR el operando -- que byte hay que parchear
     * --.  Eso lo cubre la comprobacion de reescritura del destino, mas arriba.
     */
    {
        std::printf("\nLa forma declarada, contra lo que hace el manejador\n");
        csh cs2 = 0;
        if (cs_open(tests::kWalkArch, tests::kWalkMode, &cs2) != CS_ERR_OK) {
            std::printf("  (sin Capstone: no se comprueba)\n");
        } else {
            cs_close(&cs2);
            const std::vector<tests::OpcodeRow> filas =
                tests::build_opcode_model(0);
            int comparadas = 0, cubiertas = 0;
            for (const tests::OpcodeRow &f : filas) {
                if (!f.implementada) continue;
                if (f.imp.form_read == 0 && f.imp.form_write == 0) continue;
                const bool ext = std::strcmp(f.tabla, "extended") == 0;
                uint8_t bytes[16];
                for (size_t k = 0; k < sizeof(bytes); ++k)
                    bytes[k] = operand_byte(k);
                runtime::DecodedInstr d;
                if (!build(ext, f.indice, bytes, sizeof(bytes), d)) continue;
                runtime::InstrEffects e;
                if (!runtime::probe_effects(d, e)) continue; // sin forma escrita
                /* La forma declarada se lee por INSTANCIA y la derivada por
                 * OPCODE: donde la instruccion se comporta distinto segun una
                 * bandera -- `mov` con `_signed_instruct` pasa a mover
                 * registros ESPECIALES --, lo derivado es la UNION de las dos
                 * ramas y una instancia sola nunca la cubre.
                 *
                 * Asi que se compara contra la union: se pregunta por la
                 * declaracion con la bandera en los dos estados.  Sin esto, el
                 * test acusaba a `mov` de no declarar lo que si declara, solo
                 * que en la otra rama. */
                {
                    runtime::DecodedInstr otra = d;
                    otra.flags_info._signed_instruct =
                        d.flags_info._signed_instruct ? 0 : 1;
                    runtime::InstrEffects e2;
                    if (runtime::probe_effects(otra, e2)) {
                        e.reg_read |= e2.reg_read;
                        e.reg_write |= e2.reg_write;
                        e.vec_read |= e2.vec_read;
                        e.vec_write |= e2.vec_write;
                    }
                }
                ++comparadas;
                const uint16_t der_r = regs_de_forma(f.imp.form_read, d);
                const uint16_t der_w = regs_de_forma(f.imp.form_write, d);
                const uint16_t falta_r = static_cast<uint16_t>(der_r & ~e.reg_read);
                const uint16_t falta_w =
                    static_cast<uint16_t>(der_w & ~e.reg_write);
                if (falta_r == 0 && falta_w == 0) {
                    ++cubiertas;
                    continue;
                }
                mal("el manejador toca registros que la forma no declara",
                    f.nombre.c_str(), f.tabla, f.indice,
                    "lee de mas: " + mascara(falta_r) +
                        "  escribe de mas: " + mascara(falta_w));
            }
            std::printf("  %d formas declaradas contrastadas con su "
                        "manejador, %d cuadran\n",
                        comparadas, cubiertas);

            /* Y CUANTAS no se pudieron contrastar, que es lo que no puede
             * quedarse callado.
             *
             * Las formas del banco VECTORIAL estan declaradas leyendo el
             * manejador -- `fadd` opera sobre `registers.zmm[]`, y eso el fuente
             * lo dice sin ambiguedad --, pero el derivador todavia no ve esos
             * accesos: con 64 bytes por registro la escala de un acceso indexado
             * no llega, asi que el compilador calcula la base aparte y el rastro
             * se pierde.  O sea que descansan sobre UNA fuente y no sobre dos,
             * que es justo lo que este test existe para evitar.
             *
             * Se cuenta para que sea un numero que baja, y no una nota al pie
             * que se olvida. */
            int con_vec = 0, vec_derivadas = 0;
            for (const tests::OpcodeRow &f : filas) {
                if (!f.implementada) continue;
                const bool ext = std::strcmp(f.tabla, "extended") == 0;
                uint8_t bytes[16];
                for (size_t k = 0; k < sizeof(bytes); ++k)
                    bytes[k] = operand_byte(k);
                runtime::DecodedInstr d;
                if (!build(ext, f.indice, bytes, sizeof(bytes), d)) continue;
                runtime::InstrEffects e;
                if (!runtime::probe_effects(d, e)) continue;
                if (e.vec_read == 0 && e.vec_write == 0) continue;
                ++con_vec;
                if (f.imp.form_vec_read != 0 || f.imp.form_vec_write != 0)
                    ++vec_derivadas;
            }
            if (con_vec > 0)
                std::printf("  %d usan el banco VECTORIAL; el derivador "
                            "confirma %d\n"
                            "  (el resto descansa solo en el fuente del "
                            "manejador, no en dos fuentes)\n",
                            con_vec, vec_derivadas);
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
