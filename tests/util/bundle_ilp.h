/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/bundle_ilp.h
 * @brief Cuanta independencia REAL hay dentro de un paquete.
 *
 * Que decide
 * ----------
 * El OoO que se quiere aqui no es el de una CPU: no rellena huecos de tuberia
 * --el anfitrion ya retira el 79%--, sino que REORDENA AL FORMAR para poder
 * fusionar, vectorizar y quitar redundancias.  O sea, para bajar el RECUENTO de
 * instrucciones, que es el cuello medido.
 *
 * Eso solo vale la pena si dentro del paquete hay algo que mover.  Si las k
 * instrucciones forman una cadena, el orden ya es el unico posible y no hay
 * nada que ganar.  Este test lo mide ANTES de implementar la reordenacion, para
 * no construir sobre una suposicion.
 *
 * Como se mide, y sobre que
 * -------------------------
 * Sobre los paquetes REALES: se ejecuta el programa con el interprete --el JIT
 * apagado desde dentro, que es la unica forma-- y despues se recorre la arena
 * de paquetes del proceso.  Un paquete formado una vez pero ENTRADO un millon
 * de veces pesa un millon; por eso todo se pondera por `entries`, no por
 * paquetes distintos.  Contar paquetes daria el peso al codigo frio.
 *
 * De donde sale la dependencia
 * ----------------------------
 * De `tests/util/opcode_effects.h`: la FORMA la da el desensamblador (que
 * registros nombra y cual es el destino) y los EFECTOS IMPLICITOS --banderas,
 * pila, marco, contador de programa-- salen del codigo maquina del manejador.
 * Los registros concretos se sacan desensamblando los BYTES REALES de cada
 * instruccion del paquete, no un patron inventado.
 *
 * Es CONSERVADOR a proposito
 * --------------------------
 * Cuatro decisiones tiran del resultado hacia abajo, y todas a proposito:
 *
 *   - un opcode con efectos de COTA INFERIOR (`?`) se trata como BARRERA: si no
 *     se sabe todo lo que toca, no se puede mover nada a su alrededor;
 *   - el destino de una instruccion se cuenta tambien como LECTURA, porque
 *     distinguir `mov` de `add` pediria saber si el opcode lee su destino;
 *   - toda la memoria de la VM es UN solo recurso: sin desambiguacion, dos
 *     accesos cualesquiera se ordenan entre si;
 *   - lo que transfiere control no se mueve nunca.
 *
 * Asi que lo que salga es un SUELO.  Si ya con esto hay independencia, la hay
 * de verdad; si no la hay, todavia podria aparecer al afinar el modelo, y este
 * test dice cual de las cuatro es la que aprieta.
 *
 * POR QUE ES UNA CABECERA Y NO UN TEST APARTE.  Cada `.cpp` de `tests/` produce
 * su propio binario, y esto medía sobre LOS MISMOS programas, LA MISMA arena y
 * con LA MISMA tabla que `test_bundles`: dos binarios que generan lo mismo, lo
 * ejecutan otra vez y lo imprimen dos veces.  Son dos PREGUNTAS distintas
 * -- una valida que los paquetes no cambian el resultado, esta mide cuanta
 * independencia hay dentro -- pero de un solo sujeto, asi que van en el mismo
 * test.  Aqui queda el analisis; el informe lo pide `ilp_report`.
 */

#ifndef VESTA_TESTS_BUNDLE_ILP_H
#define VESTA_TESTS_BUNDLE_ILP_H

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "runtime/bundle.h"
#include "runtime/bundle/fuse_report.h"
#include "runtime/instr_db_vm.h"
#include "runtime/decode_instruction.h"

#include "opcode_effects.h"
#include "util/ansi.h"
#include "vm_standalone.h"

namespace {

/// Lo que una instruccion toca.  Registros de VM (16 bits), campos implicitos
/// (4) y la memoria como UN solo recurso, que es todo lo que se sabe hoy.
struct Touch {
    uint32_t reg_read = 0, reg_write = 0;
    uint32_t field_read = 0, field_write = 0;
    bool mem_read = false, mem_write = false;
    /// Ni se mueve ni deja mover: transfiere control, o sus efectos son cota
    /// inferior y por tanto se desconoce parte de lo que toca.
    /// Ni se mueve ni deja mover: transfiere control, o sus efectos son cota
    /// inferior y por tanto se desconoce parte de lo que toca.
    bool barrier = true;
    bool bar_control = false; ///< transfiere control: inmovible de verdad
    bool bar_unknown = false; ///< efectos de COTA INFERIOR: limitacion del modelo
};

/**
 * @brief El opcode de una instruccion, en la tabla que le toque.
 *
 * NO es `opcode_index` a secas.  Una instruccion de la tabla PRIMARIA lleva su
 * opcode en `is_not_extended` y deja `opcode_index` a cero; solo las de la
 * extendida usan el segundo campo.  Mirar siempre `opcode_index` mete a TODAS
 * las primarias -- `push`, `pop`, `jmp`, `enter`, `call`, `ret` -- en la ranura
 * 0, que es un hueco: sale un nombre sin sentido y, peor, salen los efectos
 * de OTRA cosa.
 *
 * El reordenador de verdad (`src/runtime/bundle_reorder.cpp`) siempre lo hizo
 * bien; era este medidor el que no, y por eso decia que reordenar no aporta
 * NADA.  Se pone en una funcion para que no haya cuatro sitios que lo decidan.
 */
inline uint8_t op_index(const runtime::DecodedInstr &d) {
    return (d.flags_info.is_not_extended == 0x00)
               ? static_cast<uint8_t>(d.flags_info.opcode_index)
               : d.flags_info.is_not_extended;
}

/// Indice del modelo por (tabla, opcode), para no buscar en el vector por cada
/// instruccion de cada paquete.
struct Model {
    tests::OpcodeRow *primary[256] = {};
    tests::OpcodeRow *extended[256] = {};
    std::vector<tests::OpcodeRow> rows;

    explicit Model(std::vector<tests::OpcodeRow> r) : rows(std::move(r)) {
        for (auto &f : rows) {
            auto **t = (f.tabla[0] == 'p') ? primary : extended;
            t[f.indice & 0xFF] = &f;
        }
    }
    const tests::OpcodeRow *find(bool ext, uint16_t op) const {
        return ext ? extended[op & 0xFF] : primary[op & 0xFF];
    }
};

/**
 * @brief Que toca esta instruccion del paquete.
 *
 * Los registros salen de desensamblar sus BYTES REALES: el desensamblador es
 * quien sabe de que campo sale cada uno, y ademas da cual es el destino.
 */
Touch touch_of(runtime::ProcessVM *proc, const Model &model,
               const runtime::DecodedInstr &d) {
    Touch t;
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const tests::OpcodeRow *row = model.find(ext, op_index(d));
    if (row == nullptr) return t; // desconocido: se queda de barrera

    // Cota inferior o transferencia de control: barrera, sin mas analisis.
    if (row->salta || !row->imp.completo) {
        t.bar_control = row->salta;
        t.bar_unknown = !row->salta && !row->imp.completo;
        return t;
    }
    t.barrier = false;

    for (size_t k = 0; k < sizeof(tests::kFields) / sizeof(tests::kFields[0]);
         ++k) {
        if ((row->imp.escribe >> k) & 1u) t.field_write |= (1u << k);
        if ((row->imp.lee >> k) & 1u) t.field_read |= (1u << k);
    }

    /* La memoria, como un solo recurso.  Cualquier modo que no sea registro,
     * inmediato o sin operandos toca `vm_mem`, y sin desambiguacion no se puede
     * decir que dos accesos van a sitios distintos. */
    const std::string mode = row->modo;
    if (mode != "REG" && mode != "INMED" && mode != "NONE") {
        t.mem_read = t.mem_write = true;
    }

    // Los registros, de los bytes REALES de esta instruccion.
    uint8_t bytes[24] = {0};
    proc->vm_mem.read_bytes(d.pc, bytes, sizeof(bytes));
    disasm::DisasmOptions opts;
    opts.show_hex = false;
    opts.use_color = false;
    opts.stop_at_hlt = false;
    opts.max_bytes = sizeof(bytes);
    const auto res = disasm::disasm_bytes(bytes, sizeof(bytes), d.pc, opts);
    if (res.empty()) {
        t.barrier = true; // no se pudo leer la forma: no se mueve
        return t;
    }
    for (const auto &r : res[0].regs) {
        const uint32_t bit = 1u << (r.index & 0xF);
        /* El destino cuenta tambien como LECTURA.  Saber si un opcode lee su
         * destino (`add` si, `mov` no) pide un dato que el modelo no tiene; dar
         * por hecho que no lo lee permitiria reordenaciones invalidas. */
        if (r.dest)
            t.reg_write |= bit, t.reg_read |= bit;
        else
            t.reg_read |= bit;
    }
    return t;
}

/// Chocan?  Dos instrucciones no se pueden intercambiar si comparten un recurso
/// y al menos una lo escribe.  Una barrera choca con todo.
bool conflict(const Touch &a, const Touch &b) {
    if (a.barrier || b.barrier) return true;
    if ((a.reg_write & (b.reg_read | b.reg_write)) != 0) return true;
    if ((b.reg_write & (a.reg_read | a.reg_write)) != 0) return true;
    if ((a.field_write & (b.field_read | b.field_write)) != 0) return true;
    if ((b.field_write & (a.field_read | a.field_write)) != 0) return true;
    if ((a.mem_write && (b.mem_read || b.mem_write)) ||
        (b.mem_write && (a.mem_read || a.mem_write)))
        return true;
    return false;
}

} // namespace

namespace {

namespace {

/* ---------------------------------------------------------------------------
 * Oportunidades de FUSION
 *
 * Un par (A, B) se puede fusionar en UNA instruccion cuando A produce un valor
 * que B consume y ese valor no lo quiere nadie mas: el temporal esta MUERTO
 * despues de B.  Entonces la instruccion fusionada calcula lo mismo sin
 * materializarlo, y desaparece una instruccion de VM.
 *
 * Eso es lo unico que baja el RECUENTO, que es el cuello medido: el anfitrion
 * ya solapa (CPI 0,207) y no hay parada que recuperar.
 *
 * Se pondera por ENTRADAS al paquete, no por apariciones en el codigo: un par
 * dentro de un bucle caliente vale lo que se ejecuta, no uno.
 * ------------------------------------------------------------------------- */

/// Un par de opcodes consecutivos y lo que pesa.
struct PairStat {
    double weight = 0;   ///< veces que se ejecuta el par
    double fusable = 0;  ///< de esas, cuantas con el temporal MUERTO
    double cycles = 0;   ///< ciclos de ejecutar los dos, sumados
    uint32_t seen = 0;   ///< sitios distintos donde aparece
    double reorder = 0;  ///< fusionables SOLO si se aparta lo de en medio
    double reorder_named = 0; ///< lo mismo, apuntado al par REAL (i, consumidor)
    double hoy = 0;      ///< de las fusionables, cuantas sabe hacer YA el fusionador
};
std::map<std::string, PairStat> g_fusion;

/// Por que renuncio el fusionador, contado.  Indexado por `FuseReject`.  Es lo
/// que convierte un "0%" en una respuesta: dice si no hay material, si el
/// patron esta mal escrito o si lo que falla es otra cosa.
double g_reject[8] = {0};


/// Nombre del opcode de una instruccion del paquete.
const char *op_name(const Model &model, const runtime::DecodedInstr &d) {
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const tests::OpcodeRow *r = model.find(ext, op_index(d));
    return r ? r->nombre.c_str() : "?";
}

/* Etiqueta del opcode PARA EL INFORME: el nombre a secas es AMBIGUO -- `add`
 * son cinco opcodes distintos (reg,reg / reg,imm / SIB...) y solo uno de ellos
 * tiene variante de tres operandos.  Un informe que los junta dice que hay
 * material donde no lo hay, que es justo el fallo que costo una implementacion
 * entera del fusionador. */
std::string op_label(const Model &model, const runtime::DecodedInstr &d) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "/%02X", (unsigned)op_index(d));
    return std::string(op_name(model, d)) + buf;
}
/**
 * @brief Escribe la instruccion su destino SIN leerlo?
 *
 * Hace falta para saber si un temporal muere: si el destino tambien se lee, la
 * instruccion no lo mata, lo actualiza.
 *
 * Dos vias, y ninguna adivina:
 *
 *   - La FORMA de tres direcciones.  `adds3 rd, rs1, rs2` calcula a partir de
 *     los otros dos y pisa el destino entero.  Con dos registros la forma NO
 *     distingue `add rd, rs` de `mov rd, rs` -- lo advierte el propio
 *     desensamblador --, asi que ahi no basta.
 *   - La SEMANTICA documentada de los que copian o cargan.  `mov` escribe el
 *     destino sin leerlo (su propio manejador, `mov_wrapper`, lo dice), `mld`
 *     lo trae de memoria y `loadz`/`loadzh` lo ponen a cero antes de cargar.
 *     `movc` NO entra: es condicional, y si la condicion falla el destino se
 *     queda como estaba, o sea que lo lee.  `sext` tampoco: opera sobre su
 *     propio destino.
 *
 * Sin esta segunda via el analisis se hunde: un `mov` posterior marcaria el
 * registro como LEIDO y ningun temporal moriria nunca.  Se veia en
 * `adds3 + mov`, con 77.712 ejecuciones y solo 364 fusionables.
 */
bool writes_dest_only(const std::vector<disasm::RegOperand> &regs,
                      const char *name) {
    if (name != nullptr) {
        if (std::strcmp(name, "mov") == 0 || std::strcmp(name, "mld") == 0 ||
            std::strcmp(name, "loadz") == 0 ||
            std::strcmp(name, "loadzh") == 0)
            return true;
    }
    if (regs.size() < 3) return false;
    int dests = 0;
    for (const auto &r : regs)
        if (r.dest) ++dests;
    return dests == 1;
}

/// La forma (registros y cual es el destino) de una instruccion del paquete.
/**
 * @brief Las BANDERAS como un recurso mas de la forma, en el bit 16.
 *
 * Los registros ocupan los bits 0..15.  Las banderas van detras porque un
 * temporal muerto tambien puede ser una bandera, y mientras no estuvieron aqui
 * el analisis era CIEGO justo a la familia de fusiones mas clasica:
 * `cmp` + `setcc`, `cmp` + salto, ALU + salto.  El modelo ya sabia quien las
 * escribe y quien las lee -- sale de la base generada, igual que todo lo demas
 * --, pero ese dato solo se usaba para decidir si dos instrucciones se pueden
 * INTERCAMBIAR, no para ver si una alimenta a la otra.
 *
 * Es el mismo tipo de agujero que el de los nombres de opcode: no daba un error,
 * daba un cero -- y un cero se lee como "no hay nada que hacer".
 */
constexpr int kFlagShift = 16;

struct Shape {
    std::vector<disasm::RegOperand> regs;
    uint32_t write = 0;     ///< bit por registro escrito, mas el bit 16
    uint32_t read = 0;      ///< bit por registro leido, mas el bit 16
    bool dest_only = false; ///< el destino se pisa entero, no se acumula
};

/// Saca la forma de los BYTES REALES.
///
/// Usa el desensamblador a proposito, y aqui SI vale: esto es una herramienta
/// de analisis offline, no el camino de la VM.  La formacion del paquete no
/// puede llamarlo --construye cadenas con `snprintf`--, y por eso la forma que
/**
 * @brief Anade a la forma lo que la instruccion hace con las BANDERAS.
 *
 * Sale de la base generada, que es donde vive; el desensamblador solo ve lo que
 * la instruccion NOMBRA, y las banderas no se nombran en ningun operando.
 * Se llama desde `shape_of` para que los dos caminos que miden -- el de los
 * paquetes y el de la traza -- vean lo mismo.  Ver `kFlagShift`.
 */
void add_flags_to_shape(Shape &s, const runtime::DecodedInstr &d) {
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const runtime::vm_isa::VmInstr *v = runtime::vm_isa::vm_instr(
        ext, op_index(d));
    if (v == nullptr) return; // ranura desconocida: no se afirma nada
    if ((v->effects & runtime::vm_isa::VE_EXACT) == 0) {
        /* Cota inferior: puede tocarlas y no consta.  Se marca que las escribe
         * Y las lee, que es lo conservador -- asi ni parece que produzca un
         * valor limpio ni que deje libres las de otro. */
        s.write |= (1u << kFlagShift);
        s.read |= (1u << kFlagShift);
        return;
    }
    if (v->effects & runtime::vm_isa::VE_W_FLAGS)
        s.write |= (1u << kFlagShift);
    if (v->effects & runtime::vm_isa::VE_R_FLAGS)
        s.read |= (1u << kFlagShift);
}

/// consume la VM va en la base de datos generada.
Shape shape_of(runtime::ProcessVM *proc, const runtime::DecodedInstr &d,
                const char *name) {
    Shape s;
    uint8_t raw[16] = {0};
    const size_t n = d.flags_info.size_instr ? d.flags_info.size_instr : 16;
    proc->vm_mem.read_bytes(d.pc, raw, n < sizeof(raw) ? n : sizeof(raw));
    disasm::DisasmOptions opts;
    opts.show_hex = false;
    opts.use_color = false;
    opts.stop_at_hlt = false;
    opts.max_bytes = n;
    const auto res = disasm::disasm_bytes(raw, n, d.pc, opts);
    if (!res.empty()) s.regs = res[0].regs;
    s.dest_only = writes_dest_only(s.regs, name);
    for (const auto &r : s.regs) {
        if (r.floating) continue; // el banco ZMM va aparte; aqui no se mezcla
        const uint16_t bit = static_cast<uint16_t>(1u << (r.index & 0xF));
        if (r.dest) {
            s.write |= bit;
            if (!s.dest_only) s.read |= bit; // acumula: lo lee tambien
        } else {
            s.read |= bit;
        }
    }
    add_flags_to_shape(s, d);
    return s;
}

/**
 * @brief Esta muerto @p reg despues de la posicion @p from del paquete?
 *
 * Muerto = alguien lo PISA antes de que nadie lo lea.  Si se acaba el paquete
 * sin resolverlo, se dice que NO: el valor puede seguir vivo fuera, y darlo por
 * muerto seria justo el fallo silencioso.
 */
bool dead_after(const std::vector<Shape> &sh, uint32_t from, uint32_t reg) {
    for (uint32_t j = from + 1; j < sh.size(); ++j) {
        if (sh[j].read & reg) return false;                  // lo usa
        if ((sh[j].write & reg) && sh[j].dest_only) return true; // lo pisa
    }
    return false; // se acabo el paquete: puede vivir fuera
}

/// Ciclos de EJECUTAR una instruccion, promedio sobre las microarquitecturas.
/// Se usa exec y no el total a proposito: dentro de un paquete la
/// descodificacion ya se pago al formarlo.
double exec_cycles(const runtime::DecodedInstr &d) {
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const runtime::vm_isa::VmInstr *v = runtime::vm_isa::vm_instr(
        ext, op_index(d));
    if (!runtime::vm_isa::vm_cost_measured(v, runtime::vm_isa::VH_X86))
        return 0.0;
    return v->cost[runtime::vm_isa::VH_X86].exec_cycles_avg;
}

/// Cuenta los pares consecutivos de un paquete y cuales se podrian fusionar.
void tally_pairs(runtime::ProcessVM *proc, const Model &model,
                 const runtime::Bundle &b) {
    if (b.k < 2) return;
    const double w = (double)(b.entries ? b.entries : 1);

    std::vector<Shape> sh(b.k);
    for (uint32_t i = 0; i < b.k; ++i)
        sh[i] = shape_of(proc, b.instr[i], op_name(model, b.instr[i]));

    for (uint32_t i = 0; i + 1 < b.k; ++i) {
        std::string key = op_label(model, b.instr[i]) + " + " +
                          op_label(model, b.instr[i + 1]);
        PairStat &st = g_fusion[key];
        st.weight += w;
        ++st.seen;
        st.cycles += w * (exec_cycles(b.instr[i]) + exec_cycles(b.instr[i + 1]));

        /* Fusionable: lo que escribe la primera lo lee la segunda, y ese valor
         * no lo quiere nadie mas.  Sin la segunda condicion la fusion tendria
         * que materializar el temporal igual y no ahorraria nada. */
        const uint32_t pasa = sh[i].write & sh[i + 1].read;
        if (pasa == 0) continue;
        for (int bit = 0; bit <= kFlagShift; ++bit) {
            const uint32_t m = 1u << bit;
            if ((pasa & m) == 0) continue;
            if (dead_after(sh, i + 1, m)) {
                st.fusable += w;
                break;
            }
        }
    }
}

} // namespace

namespace {

/* ---------------------------------------------------------------------------
 * Recuento sobre la TRAZA DE EJECUCION
 *
 * El recuento por paquetes estaba sesgado, y de una forma que invertia el
 * resultado: los paquetes tienen umbral para formarse y RETIRADA automatica
 * --por debajo de 6 instrucciones por entrada devuelven la ranura--, asi que
 * el codigo con tramos cortos desaparece de la muestra.  Comparando el mismo
 * corpus a O2 y a O0 con el mismo tope de despachos salian 1.983.967 pares
 * contra 377.814: no eran dos emisores, eran dos muestras.
 *
 * Aqui se ejecuta instruccion a instruccion con los paquetes APAGADOS y se
 * mira lo que de verdad corre, en orden.  Sin umbral, sin retirada y sin
 * ventana de 32.
 *
 * La ventana deslizante da el horizonte para decidir si un temporal MUERE: se
 * mira si alguien lo pisa antes de que nadie lo lea.  Si en toda la ventana no
 * se resuelve, se dice que NO muere -- puede vivir mas alla, y darlo por
 * muerto seria el fallo silencioso.
 * ------------------------------------------------------------------------- */

/// Instrucciones de traza que se miran hacia adelante para decidir si un
/// temporal muere.  Suficiente para que la mayoria se resuelva y acotado para
/// que el recuento no dependa de cuanto se mire.
constexpr size_t kTraceWindow = 24;

struct TraceEntry {
    uint8_t field_read = 0, field_write = 0;
    bool mem = false;
    bool control = true; ///< transfiere control: nunca se cruza
    Shape shape;
    std::string name;
    std::string label; ///< `nombre/OPCODE`: lo que se imprime, sin ambiguedad
    runtime::DecodedInstr raw; ///< la instruccion tal cual, para preguntarle al fusionador
};


/**
 * @brief Efectos implicitos, de la base de datos generada.
 *
 * Hay DOS cosas distintas, y meterlas en un solo booleano "barrera" era el
 * error:
 *
 *   - **Transferir control** es una barrera de verdad.  Mover algo al otro
 *     lado de un salto cambia QUE se ejecuta, toque lo que toque.
 *   - **Efectos de COTA INFERIOR** no es una barrera: es no saberlo todo.  Y no
 *     se sabe solo de los CUATRO campos implicitos y de la memoria -- los
 *     REGISTROS siguen siendo exactos, porque los da el desensamblador de los
 *     bytes reales.  Asi que lo correcto no es "choca con todo", sino suponer
 *     el efecto MAXIMO en los ejes que si se conocen: lee y escribe los cuatro
 *     campos, y toca memoria.
 *
 * La diferencia importa: con "choca con todo", un `mov` en medio impedia
 * cualquier movimiento.  Con el efecto maximo, dos instrucciones que solo se
 * pisan en registros distintos siguen pudiendo intercambiarse.
 */
void fill_effects(TraceEntry &e, const runtime::DecodedInstr &d) {
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const runtime::vm_isa::VmInstr *v = runtime::vm_isa::vm_instr(
        ext, op_index(d));
    if (v == nullptr) {
        e.control = true; // ranura desconocida: no se mueve nada a su lado
        return;
    }
    e.control = (v->effects & runtime::vm_isa::VE_CONTROL) != 0;
    e.mem = (v->effects & runtime::vm_isa::VE_MEMORY) != 0;
    if ((v->effects & runtime::vm_isa::VE_EXACT) != 0) {
        e.field_write = static_cast<uint8_t>(v->effects & 0x0F);
        e.field_read = static_cast<uint8_t>((v->effects >> 4) & 0x0F);
    } else {
        // No se sabe todo: se supone lo peor DENTRO de lo conocido.
        e.field_write = 0x0F;
        e.field_read = 0x0F;
        e.mem = true;
    }
    /* Las banderas NO se anaden aqui: ya las puso `shape_of` en la forma, que es
     * el unico sitio que la construye.  Ponerlas tambien aqui las tendria
     * calculadas en dos, y dos productores del mismo hecho es como se separan
     * en cuanto uno cambia. */
}

/// Chocan?  Dos instrucciones no se pueden intercambiar si comparten un recurso
/// y al menos una lo escribe.  Lo que transfiere control no se cruza nunca.
bool clash(const TraceEntry &a, const TraceEntry &b) {
    if (a.control || b.control) return true;
    if (a.shape.write & (b.shape.read | b.shape.write)) return true;
    if (b.shape.write & (a.shape.read | a.shape.write)) return true;
    if (a.field_write & (b.field_read | b.field_write)) return true;
    if (b.field_write & (a.field_read | a.field_write)) return true;
    if (a.mem && b.mem) return true; // sin desambiguacion, se ordenan
    return false;
}

/**
 * @brief Se puede subir la instruccion @p j hasta quedar pegada a @p i?
 *
 * Hace falta que no choque con NADA de lo que hay en medio: si choca con una
 * sola, moverla cambiaria el resultado.  Es lo que convierte un par separado en
 * un par fusionable, y es justo lo que el reordenamiento aporta.
 */
bool can_pull_up(const std::vector<TraceEntry> &w, size_t i, size_t j) {
    for (size_t k = i + 1; k < j; ++k)
        if (clash(w[k], w[j])) return false;
    return true;
}
/// Muere @p reg dentro de la ventana, mirando desde @p from?
bool dead_in_window(const std::vector<TraceEntry> &w, size_t from,
                    uint32_t reg) {
    for (size_t j = from + 1; j < w.size(); ++j) {
        if (w[j].shape.read & reg) return false;
        if ((w[j].shape.write & reg) && w[j].shape.dest_only) return true;
    }
    return false; // sin resolver en la ventana: se supone vivo
}

/// Cuenta el par que encabeza la ventana, mirando tambien los consumidores que
/// hoy NO estan pegados: si lo de en medio se puede apartar, el par es
/// fusionable IGUAL, y eso es exactamente lo que aporta reordenar.
void tally_window(const std::vector<TraceEntry> &w) {
    if (w.size() < 2) return;
    const std::string key = w[0].label + " + " + w[1].label;
    PairStat &st = g_fusion[key];
    st.weight += 1;
    ++st.seen;
    /* OJO: aqui NO se mira si la primera es "barrera".
     *
     * Ser barrera significa que no se puede MOVER, y eso es una propiedad del
     * REORDENAMIENTO, no de la fusion.  Dos instrucciones que ya estan pegadas
     * se fusionan sin mover nada: la fusionada hace lo que hacian las dos, en
     * el mismo sitio y en el mismo orden.
     *
     * Confundirlo hundia el analisis justo donde mas material hay: en codigo
     * sin optimizar el productor es casi siempre un `mov`, `mov` sale como
     * cota inferior, y se descartaba el par entero.  Salia que el codigo SIN
     * optimizar tenia MENOS que fusionar que el optimizado, que es imposible.
     *
     * La barrera se comprueba donde toca: en `can_pull_up`, que es lo unico
     * que mueve algo. */

    for (int bit = 0; bit <= kFlagShift; ++bit) {
        const uint32_t m = 1u << bit;
        if ((w[0].shape.write & m) == 0) continue;
        /* Se busca al PRIMER consumidor, este pegado o no.  Se para en cuanto
         * alguien pisa el registro: a partir de ahi ya no es el mismo valor. */
        for (size_t j = 1; j < w.size(); ++j) {
            if (w[j].shape.read & m) {
                if (!dead_in_window(w, j, m)) break; // el valor sigue vivo
                if (j == 1) {
                    st.fusable += 1; // ya estan pegados
                    /* Y de esas, cuantas sabe hacer el fusionador REAL hoy, y
                     * de las que no, POR QUE no.  Se le pregunta a el, no se
                     * deduce del nombre: es la unica forma de que el informe y
                     * la implementacion no se separen -- y sin la razon, un 0%
                     * no distingue "no hay material" de "el patron esta mal
                     * escrito". */
                    const runtime::FuseReject por =
                        runtime::fuse_would_apply(w[0].raw, w[1].raw);
                    if (por == runtime::FuseReject::None)
                        st.hoy += 1;
                    else
                        g_reject[static_cast<size_t>(por)] += 1;
                } else if (can_pull_up(w, 0, j)) {
                    st.reorder += 1; // hace falta apartar lo de en medio
                    /* La clave del par pasa a ser la REAL: lo que se fusiona es
                     * la primera con su consumidor, no con su vecina. */
                    PairStat &rk = g_fusion[w[0].label + " + " + w[j].label];
                    rk.reorder_named += 1;
                }
                return;
            }
            if ((w[j].shape.write & m) && w[j].shape.dest_only) return;
        }
    }
}

/**
 * @brief Ejecuta el programa paso a paso y cuenta los pares que se ejecutan.
 *
 * Los paquetes van APAGADOS: aqui interesa el flujo real, no el que sobrevive
 * al umbral de formacion.
 *
 * @return Instrucciones ejecutadas.
 */
uint64_t trace_pairs(runtime::ProcessVM *proc, const Model &model,
                     uint64_t cap) {
    proc->bundles_on = false;
    proc->scheduler.has_hooks = false;
    std::vector<TraceEntry> win;
    uint64_t n = 0;

    while (proc->state != runtime::HALT && proc->state != runtime::DEAD &&
           proc->err_thread == runtime::THREAD_NO_ERROR && n < cap) {
        const uint64_t pc = proc->registers.rip.raw();
        runtime::DecodedInstr *cached = runtime::icache_lookup(proc, pc);
        if (cached != nullptr && proc->decoded_ptr != nullptr)
            proc->decoded_ptr = cached;
        else
            runtime::decode_instruction(proc);
        if (proc->decoded_ptr == nullptr) break;

        const runtime::DecodedInstr &d = *proc->decoded_ptr;
        if (d.flags_info.is_not_extended == 0x00 &&
            d.flags_info.opcode_index ==
                static_cast<uint16_t>(bytecode::Opcodes::HLT))
            break;

        TraceEntry e;
        e.name = op_name(model, d);
        e.label = op_label(model, d);
        e.raw = d;
        e.shape = shape_of(proc, d, e.name.c_str());
        fill_effects(e, d);
        win.push_back(std::move(e));
        if (win.size() > kTraceWindow) {
            tally_window(win);
            win.erase(win.begin());
        }

        if (proc->reductions_remaining <= 1)
            proc->reductions_remaining = reductions_remaining_default;
        --proc->reductions_remaining;
        const runtime::vm_event ev = runtime::execute_instruction(proc);
        ++n;
        if (ev == runtime::EVT_HALT || ev == runtime::EVT_ERROR ||
            ev == runtime::EVT_IO_WAIT)
            break;
    }
    return n;
}

} // namespace

/// Lo medido de un paquete.

/* Cuanto `?` aporta cada opcode, ponderado por entradas.
 *
 * Sin esto, "el 70% son barreras" no es accionable: no dice cuales.  Y no hace
 * falta cerrar las 73 filas de cota inferior, solo las que de verdad se
 * EJECUTAN -- que son muchas menos, porque el codigo caliente usa un punado de
 * opcodes. */
std::map<std::string, double> g_unknown_weight;
struct BundleStat {
    uint32_t k = 0;
    uint32_t critical = 0;   ///< cadena de dependencias mas larga
    uint32_t pairs = 0;      ///< pares (i<j) en total
    uint32_t free_pairs = 0; ///< pares que se podrian intercambiar
    uint32_t barriers = 0;   ///< instrucciones que no se mueven
    uint32_t bar_control = 0;///< ...por transferir control
    uint32_t bar_unknown = 0;///< ...por efectos de cota inferior
    uint64_t entries = 0;    ///< veces que se entro a este paquete
};

/**
 * @brief Analiza un paquete: cadena critica y pares libres.
 *
 * La CADENA CRITICA es lo que decide.  Con k instrucciones en una sola cadena
 * no hay nada que reordenar; con una cadena de 3 sobre k=30 hay diez niveles
 * independientes que se pueden juntar para fusionar o vectorizar.
 */
BundleStat analyze(runtime::ProcessVM *proc, const Model &model,
                   const runtime::Bundle &b) {
    BundleStat s;
    s.k = b.k;
    s.entries = b.entries;
    if (b.k == 0) return s;

    std::vector<Touch> t(b.k);
    for (uint32_t i = 0; i < b.k; ++i) {
        t[i] = touch_of(proc, model, b.instr[i]);
        if (t[i].barrier) ++s.barriers;
        if (t[i].bar_control) ++s.bar_control;
        if (t[i].bar_unknown) {
            ++s.bar_unknown;
            /* El nombre del opcode, para saber cual cerrar primero.  El peso es
             * ENTRADAS: da igual que un opcode raro sea cota inferior si no se
             * ejecuta nunca. */
            const bool ext = (b.instr[i].flags_info.is_not_extended == 0x00);
            const tests::OpcodeRow *r =
                model.find(ext, op_index(b.instr[i]));
            if (r != nullptr)
                g_unknown_weight[r->nombre] += (double)(b.entries ? b.entries : 1);
        }
    }

    /* Nivel de cada instruccion: 1 + el mayor nivel de las anteriores con las
     * que choca.  Como se recorre en orden y solo se mira hacia atras, sale la
     * cadena mas larga sin construir el grafo. */
    std::vector<uint32_t> level(b.k, 1);
    for (uint32_t j = 0; j < b.k; ++j) {
        for (uint32_t i = 0; i < j; ++i) {
            ++s.pairs;
            if (conflict(t[i], t[j])) {
                if (level[i] + 1 > level[j]) level[j] = level[i] + 1;
            } else {
                ++s.free_pairs;
            }
        }
        if (level[j] > s.critical) s.critical = level[j];
    }
    return s;
}

} // namespace

namespace tests {

/**
 * @brief Mide y publica la independencia dentro de los paquetes.
 *
 * Vuelve a EJECUTAR cada programa por su cuenta (con `VmStandalone`) porque el
 * analisis necesita la arena viva y con los paquetes ya calientes, y quien
 * llama ya solto la suya.
 *
 * @param ficheros Los `.velb` a analizar.
 * @param detalle  Anade las entradas ponderadas por programa.
 * @param tope     Tope de instrucciones por programa.
 * @return 0 si pudo analizar algo.
 */
inline int ilp_report(const std::vector<std::string> &ficheros, bool detalle,
                      uint64_t tope = 20000000) {
#if !VM_BUNDLES
    (void)ficheros;
    (void)detalle;
    (void)tope;
    std::fprintf(stderr, "construido sin VM_BUNDLES: no hay paquetes que "
                         "analizar\n");
    return 3;
#else
    const Model model(tests::build_opcode_model());
    const char *B = ansi::c(ansi::BOLD);
    const char *D = ansi::c(ansi::DIM);
    const char *R = ansi::c(ansi::RESET);

    std::printf("\n%s%s%s\n", D, std::string(108, '=').c_str(), R);
    std::printf("%sIndependencia dentro de los paquetes%s\n", B, R);
    std::printf("  Ponderado por ENTRADAS, no por paquetes: uno formado una vez"
                " y entrado\n  un millon de veces pesa un millon.\n\n");

    /* QUE MIDE CADA COLUMNA.  Sin esto son seis numeros sin nombre, y la
     * conclusion -- si merece la pena reordenar al formar -- depende justo de
     * saber cual de ellos aprieta. */
    std::printf("%sColumnas:%s\n", B, R);
    std::printf("  %spaquetes%s   cabeceras vivas analizadas.\n", D, R);
    std::printf("  %sk medio%s    instrucciones por paquete (de %d).\n", D, R,
                BUNDLE_MAX);
    std::printf("  %scadena%s     largo de la cadena de dependencias mas larga "
                "de dentro.  Si vale\n"
                "             lo mismo que `k medio`, el orden ya es el unico "
                "posible: no hay\n"
                "             NADA que mover, y reordenar no daria nada.\n",
                D, R);
    std::printf("  %slibres%%%s    pares consecutivos SIN dependencia entre "
                "ellos: lo que se podria\n"
                "             mover.  Cuanto MAS, mas margen.\n",
                D, R);
    std::printf("  %ssalta%%%s     instrucciones que no se mueven nunca porque "
                "transfieren control.\n"
                "             Es un limite REAL del programa.\n",
                D, R);
    std::printf("  %s?%%%s        instrucciones cuyos efectos el modelo solo "
                "acota por debajo, asi\n"
                "             que se tratan como barrera por prudencia.  Es un "
                "limite del MODELO,\n"
                "             no del programa: si manda esta columna, lo que "
                "toca es afinarlo,\n"
                "             porque reordenar sin saber que se toca es mover "
                "a ciegas.\n\n",
                D, R);

    // Los anchos son los de las filas contando el `%` que llevan pegado: 9 en
    // los tres porcentajes con dos digitos y 8 en el ultimo.
    std::printf("%s%-28s %8s %8s %8s %9s %9s %8s%s\n", B, "programa",
                "paquetes", "k medio", "cadena", "libres%", "salta%", "?%", R);
    std::printf("%s%s%s\n", D, std::string(108, '-').c_str(), R);

    double g_k = 0, g_crit = 0, g_bar = 0, g_free = 0, g_pairs = 0, g_ent = 0;
    double g_bctl = 0, g_bunk = 0;
    uint64_t g_bundles = 0;

    for (const std::string &f : ficheros) {
        tests::VmStandalone s;
        tests::vm_standalone_open(s, f);
        if (!s.ok()) {
            std::printf("%-28s  no carga: %s\n", f.c_str(), s.error.c_str());
            continue;
        }
        s.proc->bundles_on = true;
        tests::vm_standalone_run(s.proc, tope);

        /* Segunda pasada sobre un proceso LIMPIO para el recuento de pares:
         * por la traza real, sin la lente del paquete.  Ver `trace_pairs`. */
        {
            tests::VmStandalone t;
            tests::vm_standalone_open(t, f);
            if (t.ok()) trace_pairs(t.proc, model, tope);
        }

        auto *arena =
            reinterpret_cast<runtime::BundleArena *>(s.proc->bundle_arena);
        if (arena == nullptr || arena->total() == 0) {
            std::printf("%-28s  no se formo ningun paquete\n", f.c_str());
            continue;
        }

        double k = 0, crit = 0, bar = 0, fp = 0, pr = 0, ent = 0;
        double bctl = 0, bunk = 0;
        uint64_t n = 0;
        /* Se recorre la region VIVA por indice.  Antes se paseaba por los
         * bloques a mano; con la cache de doble region eso ya no vale -- hay
         * dos, y la vieja puede estar a medio reciclar --, asi que la region
         * expone `at()` y quien recorre no tiene que saber como esta troceada. */
        {
            const auto &half = arena->live();
            for (uint32_t i = 0; i < half.used; ++i) {
                const runtime::Bundle *bp = half.at(i);
                if (bp == nullptr) break;
                const BundleStat st = analyze(s.proc, model, *bp);
                if (st.k == 0) continue;
                ++n;
                /* El peso es ENTRADAS: un paquete que nadie ejecuta no dice
                 * nada del programa.  Se suma 1 como minimo para que los
                 * formados y nunca entrados no desaparezcan del recuento. */
                const double w = (double)(st.entries ? st.entries : 1);
                ent += w;
                k += w * st.k;
                crit += w * st.critical;
                bar += w * st.barriers;
                bctl += w * st.bar_control;
                bunk += w * st.bar_unknown;
                fp += w * st.free_pairs;
                pr += w * st.pairs;
            }
        }
        if (n == 0 || ent == 0) continue;
        if (n == 0 || ent == 0) continue;
        const size_t slash = f.find_last_of("/\\");
        const std::string corto =
            (slash == std::string::npos) ? f : f.substr(slash + 1);
        /* `libres%` cuanto mas alto mejor (hay margen para mover); `?%` cuanto
         * mas alto PEOR, porque es lo que el modelo no sabe. */
        const double libres = pr > 0 ? 100.0 * fp / pr : 0.0;
        const double desconocido = 100.0 * bunk / k;
        std::printf("%s%-28s%s %8llu %8.2f %s%8.2f%s %s%8.1f%%%s %8.1f%% "
                    "%s%7.1f%%%s\n",
                    ansi::c(ansi::BR_CYAN), corto.c_str(), R,
                    (unsigned long long)n, k / ent,
                    /* La cadena critica en verde cuando es CORTA respecto a k:
                     * ahi es donde hay niveles independientes. */
                    (crit / ent) < 0.75 * (k / ent) ? ansi::c(ansi::BR_GREEN)
                                                    : ansi::c(ansi::BR_RED),
                    crit / ent, R,
                    libres >= 30.0   ? ansi::c(ansi::BR_GREEN)
                    : libres >= 10.0 ? ansi::c(ansi::BR_YELLOW)
                                     : ansi::c(ansi::BR_RED),
                    libres, R, 100.0 * bctl / k,
                    desconocido >= 30.0   ? ansi::c(ansi::BR_RED)
                    : desconocido >= 10.0 ? ansi::c(ansi::BR_YELLOW)
                                          : ansi::c(ansi::BR_BLACK),
                    desconocido, R);
        if (detalle)
            std::printf("      entradas ponderadas: %.0f\n", ent);
        g_bundles += n;
        g_k += k;
        g_crit += crit;
        g_bar += bar;
        g_bctl += bctl;
        g_bunk += bunk;
        g_free += fp;
        g_pairs += pr;
        g_ent += ent;
    }

    if (g_ent > 0) {
        std::printf("%s%s%s\n", D, std::string(108, '-').c_str(), R);
        std::printf("%s%-28s %8llu %8.2f %8.2f %8.1f%% %8.1f%% %7.1f%%%s\n", B,
                    "TOTAL", (unsigned long long)g_bundles, g_k / g_ent,
                    g_crit / g_ent,
                    g_pairs > 0 ? 100.0 * g_free / g_pairs : 0.0,
                    100.0 * g_bctl / g_k, 100.0 * g_bunk / g_k, R);
        std::printf("\n  k medio / cadena critica = %.2f niveles "
                    "independientes por paquete.\n",
                    g_crit > 0 ? g_k / g_crit : 0.0);
        /* La columna que decide cual es el limite REAL.  Si `?%` manda, lo que
         * frena no es el programa sino lo que el modelo no sabe: son
         * instrucciones cuyos efectos son COTA INFERIOR, y por prudencia se
         * tratan como barrera.  Afinar el modelo las libera; reordenar sin
         * afinarlo seria mover a ciegas. */
        std::printf("  salta%% = no se mueve nunca (transfiere control).\n"
                    "  ?%%     = el modelo NO sabe todo lo que toca, asi que "
                    "se trata como barrera.\n");

    /* --- Que pares merece la pena convertir en UNA instruccion ---
     *
     * Ordenado por peso de EJECUCION, no por apariciones: lo que importa es lo
     * que corre, no lo que ocupa sitio en el fichero. */
    {
        std::vector<std::pair<double, std::string>> orden;
        for (const auto &kv : g_fusion)
            if (kv.second.fusable + kv.second.reorder_named > 0)
                orden.push_back(
                    {kv.second.fusable + kv.second.reorder_named, kv.first});
        std::sort(orden.begin(), orden.end(),
                  [](const auto &a, const auto &b) { return a.first > b.first; });

        double total_fus = 0, total_w = 0, total_re = 0, total_hoy = 0;
        for (const auto &kv : g_fusion) {
            total_fus += kv.second.fusable;
            total_re += kv.second.reorder;
            total_w += kv.second.weight;
            total_hoy += kv.second.hoy;
        }
        std::printf("\nPares consecutivos que se podrian convertir en UNA "
                    "instruccion\n");
        std::printf("  Fusionable = la primera produce un valor que la segunda "
                    "consume\n  y que NADIE mas quiere (temporal muerto).  Es "
                    "lo unico que baja el\n  RECUENTO, que es el cuello "
                    "medido.\n\n");
        std::printf("  ya adyacentes            : %8.0f (%.1f%%)\n", total_fus,
                    total_w > 0 ? 100.0 * total_fus / total_w : 0.0);
        std::printf("  SOLO tras reordenar      : %8.0f (%.1f%%)  <- lo que "
                    "aporta mover\n",
                    total_re, total_w > 0 ? 100.0 * total_re / total_w : 0.0);
        std::printf("  total fusionable         : %8.0f (%.1f%%)  de %.0f "
                    "instrucciones ejecutadas\n\n",
                    total_fus + total_re,
                    total_w > 0 ? 100.0 * (total_fus + total_re) / total_w : 0.0,
                    total_w);
        /* Lo que el fusionador sabe hacer HOY, contestado por EL, no deducido
         * del nombre del opcode.  Es la cifra que decide si hay trabajo o hace
         * falta un opcode nuevo, y la que faltaba: sin ella la tabla de arriba
         * se leia como "hay un 38% pendiente" cuando ese 38% pedia
         * instrucciones que no existen. */
        std::printf("  al alcance del ABI de HOY: %8.0f (%.1f%% del "
                    "fusionable)\n",
                    total_hoy,
                    (total_fus + total_re) > 0
                        ? 100.0 * total_hoy / (total_fus + total_re)
                        : 0.0);
        std::printf("  pide opcodes NUEVOS      : %8.0f (%.1f%%)\n\n",
                    total_fus + total_re - total_hoy,
                    (total_fus + total_re) > 0
                        ? 100.0 * (total_fus + total_re - total_hoy) /
                              (total_fus + total_re)
                        : 0.0);

        /* Y de quien es la culpa.  Sin esto, un 0% no dice si es que no hay
         * material, si el patron del fusionador esta mal escrito o si lo que
         * falla es el modelo que trae los pares. */
        double rechazo_total = 0;
        for (size_t i = 1; i < 8; ++i) rechazo_total += g_reject[i];
        if (rechazo_total > 0) {
            std::printf("  Por que renuncia el fusionador:\n");
            for (size_t i = 1; i < 8; ++i) {
                if (g_reject[i] <= 0) continue;
                std::printf("    %-40s %10.0f (%.1f%%)\n",
                            runtime::fuse_reject_name(
                                static_cast<runtime::FuseReject>(i)),
                            g_reject[i], 100.0 * g_reject[i] / rechazo_total);
            }
            std::printf("\n");
        }

        /* La tabla lleva ACUMULADO y no corta en seco.  Un top-N sin acumulado
         * no dice si esas filas son el material o solo la punta: la cola puede
         * pesar mas que la cabeza y no se ve.  Se imprime hasta cubrir el 95% y
         * lo que quede se resume en una linea, para no confundir "no sale" con
         * "no hay". */
        std::printf("  %-28s %12s %10s %10s %8s %6s\n", "par", "ejecuciones",
                    "adyacente", "reordenando", "hoy", "acum%");
        const double total_orden = total_fus + total_re;
        double acumulado = 0;
        size_t mostradas = 0;
        for (size_t i = 0; i < orden.size(); ++i) {
            const PairStat &st = g_fusion[orden[i].second];
            acumulado += orden[i].first;
            const double pct =
                total_orden > 0 ? 100.0 * acumulado / total_orden : 0.0;
            std::printf("  %-28s %12.0f %10.0f %10.0f %8.0f %5.1f%%\n",
                        orden[i].second.c_str(), st.weight, st.fusable,
                        st.reorder_named, st.hoy, pct);
            ++mostradas;
            if (pct >= 95.0) break;
        }
        if (mostradas < orden.size()) {
            double resto = 0, resto_hoy = 0;
            for (size_t i = mostradas; i < orden.size(); ++i) {
                resto += orden[i].first;
                resto_hoy += g_fusion[orden[i].second].hoy;
            }
            std::printf("  %-28s %12s %10.0f %10s %8.0f %5.1f%%\n",
                        ("(cola: " + std::to_string(orden.size() - mostradas) +
                         " pares mas)")
                            .c_str(),
                        "", resto, "", resto_hoy, 100.0);
        }
    }
        /* Cuales cerrar primero.  Es la lista de trabajo: cada uno de estos es
         * un opcode caliente cuyos efectos son cota inferior, y mientras lo
         * sean no se puede mover nada a su alrededor. */
        std::vector<std::pair<double, std::string>> peor;
        for (const auto &kv : g_unknown_weight)
            peor.push_back({kv.second, kv.first});
        std::sort(peor.begin(), peor.end(),
                  [](const auto &a, const auto &b) { return a.first > b.first; });
        std::printf("\n  Opcodes que aportan el `?`, por peso de ejecucion:\n");
        double suma = 0;
        for (const auto &p : peor) suma += p.first;
        for (size_t i = 0; i < peor.size() && i < 12; ++i)
            std::printf("    %-14s %5.1f%%\n", peor[i].second.c_str(),
                        suma > 0 ? 100.0 * peor[i].first / suma : 0.0);
    }
    return 0;
#endif
}

} // namespace tests

#endif // VESTA_TESTS_BUNDLE_ILP_H
