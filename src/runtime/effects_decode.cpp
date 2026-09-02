/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/effects_decode.cpp
 * @brief Que toca cada instruccion: la forma de sus operandos y sus efectos.
 *
 * Como se reparte el trabajo
 * --------------------------
 * La base de datos generada (`instr_db_vm.h`) ya guarda lo que vale para TODAS
 * las instancias de un opcode: los campos implicitos, si transfiere control y si
 * lo derivado es completo.  Eso NO se repite aqui; se lee.
 *
 * Lo que anade este fichero son las dos cosas que una tabla por opcode no puede
 * tener:
 *
 *   - la FORMA -- que registro concreto se lee y cual se escribe --, que depende
 *     de los BYTES de esta instruccion;
 *   - el ESTRECHAMIENTO -- que campos implicitos toca DE VERDAD esta vez --,
 *     cuando los operandos lo deciden.
 *
 * Salto calculado, NO punteros a funcion NI `switch`
 * ---------------------------------------------------
 * El despacho es el mismo idioma que el `run_loop`: una tabla de direcciones de
 * etiqueta y un `goto *`.  Las dos alternativas se descartaron por motivos
 * distintos:
 *
 *   - **Tabla de punteros a FUNCION.**  Cuesta la llamada, la convencion y el
 *     predictor.  Y, sobre todo, **no se puede ANALIZAR**: es literalmente el
 *     patron que dejaba los efectos sin derivar -- el recorredor del codigo
 *     maquina se para en un `call rax` porque el destino solo existe al
 *     ejecutar.  Escribir el descodificador de efectos con esa forma seria
 *     reproducir el problema que existe para cerrar.
 *   - **`switch`.**  Mejor, pero el compilador le pone su comprobacion de rango
 *     y concentra TODOS los destinos en un solo salto indirecto, que es el que
 *     el predictor falla.  Con salto calculado el indice ya viene acotado por
 *     construccion (8 bits mas el bit de tabla) y cada sitio puede tener su
 *     propio salto.
 *
 * Los ayudantes de cada familia son `inline`: no hay llamada, solo el salto.
 *
 * Una etiqueta por FAMILIA, no por opcode
 * ---------------------------------------
 * Las instrucciones de una misma familia comparten formato, asi que comparten
 * etiqueta.  Los nueve opcodes de ALU de tres operandos apuntan todos a
 * `L_ALU3`, y el dia que se anada un `div3` basta con apuntarlo ahi.
 *
 * Lo que no se apunte queda en `L_UNDECLARED`, con `exact` en false.  Un
 * opcode que nadie haya declarado no se optimiza, en vez de optimizarse mal.
 */

#include "runtime/effects_decode.h"

#include <cstdio>
#include <cstdlib>
#include <string>

#include "runtime/instr_db_vm.h"
#include "vx/diag/diag_catalog.h"

namespace runtime {
namespace {

/// Marca en @p e que se LEE el registro que vive en @p slot.
inline void mark_read(const DecodedInstr &d, InstrEffects &e, uint8_t slot) {
    e.reg_read |= static_cast<uint16_t>(1u << (reg_slot_get(d, slot) & 0x0F));
}

/// Marca el destino: se ESCRIBE, y se apunta DONDE vive para poder cambiarlo.
inline void mark_write(const DecodedInstr &d, InstrEffects &e, uint8_t slot,
                       bool kill) {
    const uint8_t r = reg_slot_get(d, slot);
    e.reg_write |= static_cast<uint16_t>(1u << (r & 0x0F));
    e.dest_reg = r;
    e.dest_slot = slot;
    e.dest_is_kill = kill;
    /* Si el destino NO se pisa entero, la instruccion tambien lo LEE: `add rd,
     * rs` acumula sobre lo que hubiera.  Sin esto, un temporal pareceria muerto
     * donde solo estaba siendo actualizado. */
    if (!kill) e.reg_read |= static_cast<uint16_t>(1u << (r & 0x0F));
}

/**
 * @brief ALU de TRES operandos (0x73-0x7B): `adds3 rd, rs1, rs2`.
 *
 * `byte2 = (rs1 << 4) | rd`, `byte3 = (rs2 << 4) | flags`, y el decoder deja
 * byte2 en `reg1` y byte3 en `reg2`.
 *
 * El destino se pisa ENTERO: se calcula a partir de los otros dos y no se lee.
 * Es lo que permite que estas MATEN un temporal, que es la mitad de las
 * fusiones posibles.
 */
inline void form_alu3(const DecodedInstr &d, InstrEffects &e) {
    mark_write(d, e, RS_REG1_LO, /*kill=*/true);
    mark_read(d, e, RS_REG1_HI);
    mark_read(d, e, RS_REG2_HI);
}

/**
 * @brief ALU binaria registro-registro: `add rd, rs`.
 *
 * Convencion A: el decoder deja los DOS numeros de registro directos, `rd` en
 * `reg1` y `rs` en `reg2`.
 *
 * El destino se ACUMULA -- `add rd, rs` es `rd += rs` --, asi que tambien se lee
 * y no mata ningun temporal.
 */
inline void form_alu_bin(const DecodedInstr &d, InstrEffects &e) {
    mark_write(d, e, RS_REG1, /*kill=*/false);
    mark_read(d, e, RS_REG2);
}

/**
 * @brief `cmp rd, rs`: compara y NO escribe ningun registro.
 *
 * Va aparte de la ALU binaria justo por eso: comparte formato pero no efecto.
 * Meterla con las demas le atribuiria una escritura que no hace, y eso impide
 * fusiones que si son legales.
 */
inline void form_cmp(const DecodedInstr &d, InstrEffects &e) {
    mark_read(d, e, RS_REG1);
    mark_read(d, e, RS_REG2);
}

/**
 * @brief `mov rd, rs` y sus variantes contra un registro ESPECIAL.
 *
 * Aqui esta el estrechamiento que justifica todo esto.  Por opcode, `mov` tiene
 * que declarar que puede escribir cualquiera de los cuatro campos implicitos,
 * porque con `s == 1` mueve contra un registro especial y CUAL sale del nibble
 * bajo de `reg2`.  Por instancia no hay ninguna duda.
 *
 * El reparto es el de `read_special_table`/`write_special_table`:
 *
 *     0..3   cursores  -- no tocan ninguno de los cuatro campos
 *     4..7   reservados
 *     8      RIP     -> contador de programa
 *     9      RBP     -> marco
 *     10     RSP     -> pila
 *     11     RFLAGS  -> banderas
 *
 * Con `s == 0` es un `mov` normal entre registros generales: no toca NINGUN
 * campo implicito, y el destino se pisa entero.
 */
inline void form_mov(const DecodedInstr &d, InstrEffects &e) {
    /* Se recalculan los campos: la base venia del opcode, que tiene que decir
     * "cualquiera de los cuatro". */
    e.field_read = 0;
    e.field_write = 0;

    if (d.flags_info._signed_instruct == 0) {
        mark_write(d, e, RS_REG1, /*kill=*/true);
        mark_read(d, e, RS_REG2);
        return;
    }

    /* El reparto, como TABLA: un indexado en vez de una cadena de
     * comparaciones.  Los ceros son los cursores (0..3) y las ranuras
     * reservadas (4..7 y 12..15), que no tocan ninguno de los cuatro campos. */
    static constexpr uint8_t kSpecialField[16] = {
        0, 0, 0, 0,                            // 0..3   cursores
        0, 0, 0, 0,                            // 4..7   reservados
        EF_PC, EF_FRAME, EF_STACK, EF_FLAGS,   // 8..11  rip, rbp, rsp, rflags
        0, 0, 0, 0,                            // 12..15 reservados
    };
    const uint8_t field = kSpecialField[d.data_instruction.reg_data.reg2 & 0x0F];

    if (d.flags_info.direction == 0) {
        // `mov r_ext, r`: el especial se ESCRIBE con el valor del general.
        e.field_write = field;
        mark_read(d, e, RS_REG1);
    } else {
        // `mov r, r_ext`: el especial se LEE y el general se pisa entero.
        e.field_read = field;
        mark_write(d, e, RS_REG1, /*kill=*/true);
    }
}

/**
 * @brief Un opcode sin forma declarada TERMINA el programa.
 *
 * No es permisividad al reves: es la unica forma de que esto se acabe de
 * escribir.  Si "no se la forma" fuese una respuesta valida, los opcodes que
 * faltan se quedarian sin declarar indefinidamente -- nadie los echaria de menos
 * porque el programa seguiria corriendo -- y el modelo estaria eternamente a
 * medias.  Muriendo aqui, cada opcode que se ejecute y no este declarado sale a
 * la luz con nombre y sitio.
 *
 * Es coherente con el resto: en una VM PROPIA no puede haber instrucciones cuyos
 * efectos no se conozcan.  Son NUESTRAS instrucciones.
 *
 * Y por eso este descodificador no se enchufa a la VM hasta que las 242 esten:
 * mientras tanto solo lo usan los tests, que es donde debe doler.
 */
[[noreturn]] void fail_undeclared(const vm_isa::VmInstr *v, bool ext,
                                  uint8_t op) {
    /* El texto NO se escribe aqui: sale del catalogo, con su codigo estable y
     * en todos los idiomas.  Que sea un fallo del motor y no de compilacion no
     * cambia nada -- quien lo lee tiene el mismo derecho a leerlo en su idioma
     * que quien lee un error del compilador. */
    char opcode[8];
    std::snprintf(opcode, sizeof(opcode), "0x%02X", op);
    const std::string nombre =
        (v != nullptr && v->name != nullptr) ? v->name : "?";
    const std::string tabla = ext ? "extended" : "primary";

    std::fprintf(stderr, "\n%s\n%s\n",
                 vx::diag::format("VX7027", {nombre, tabla, opcode}).c_str(),
                 vx::diag::format("VX7028", {}).c_str());
    std::abort();
}

/**
 * @brief El cuerpo comun.  `fatal` decide que pasa si la forma no esta.
 *
 * Las dos entradas publicas se diferencian SOLO en eso, y comparten cuerpo para
 * que no puedan divergir: si el inventario y el runtime respondieran cosas
 * distintas, el inventario dejaria de servir para saber que falta.
 *
 * @return true si la FORMA esta declarada.  Si los efectos son ademas exactos
 *         lo dice `out.exact`, que son dos preguntas distintas: la forma puede
 *         estar declarada y los campos implicitos seguir siendo una cota
 *         inferior porque el manejador despacha a algo que solo existe al
 *         ejecutar.
 */
inline bool decode_effects_impl(const DecodedInstr &d, InstrEffects &out,
                                bool fatal) {
    out = InstrEffects{};

    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const uint8_t op = static_cast<uint8_t>(d.flags_info.opcode_index);

    /* La base, de la tabla generada: los campos implicitos, si transfiere
     * control y si lo derivado es completo.  Nada de eso se recalcula aqui. */
    const vm_isa::VmInstr *v = vm_isa::vm_instr(ext, op);
    if (v == nullptr) return false; // ranura inexistente: nada se mueve

    out.field_write = static_cast<uint8_t>(v->effects & 0x0F);
    out.field_read = static_cast<uint8_t>((v->effects >> 4) & 0x0F);
    out.control = (v->effects & vm_isa::VE_CONTROL) != 0;
    out.mem_read = out.mem_write = (v->effects & vm_isa::VE_MEMORY) != 0;

    /* Indice del salto, igual que en el `run_loop`: 0..255 la tabla primaria,
     * 0x100..0x1FF la extendida.  Acotado por construccion, asi que el salto no
     * necesita comprobacion de rango. */
    const unsigned idx = ext ? (0x100u | op) : op;

    // El salto calculado es una extension de GNU; se silencia igual que en el
    // `run_loop` del planificador, que usa el mismo idioma.
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpedantic"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

#if defined(__GNUC__)
    /* Tabla de destinos.  Se rellena una vez; el resto de las ejecuciones es una
     * rama predicha y un salto.  La escritura concurrente es benigna: dos hilos
     * escribirian los MISMOS valores. */
    static void *dispatch[512];
    static bool dispatch_ready = false;
    if (__builtin_expect(!dispatch_ready, 0)) {
        for (unsigned i = 0; i < 512; ++i) dispatch[i] = &&L_UNDECLARED;

        // ALU binaria registro-registro (convencion A).
        dispatch[0x100 | 0x05] = &&L_ALU_BIN; // add
        dispatch[0x100 | 0x08] = &&L_ALU_BIN; // sub
        dispatch[0x100 | 0x0B] = &&L_ALU_BIN; // mul
        dispatch[0x100 | 0x0E] = &&L_ALU_BIN; // div
        dispatch[0x100 | 0x17] = &&L_ALU_BIN; // and
        dispatch[0x100 | 0x18] = &&L_ALU_BIN; // or
        dispatch[0x100 | 0x19] = &&L_ALU_BIN; // xor
        dispatch[0x100 | 0x1B] = &&L_ALU_BIN; // shl
        dispatch[0x100 | 0x1C] = &&L_ALU_BIN; // shr
        dispatch[0x100 | 0x1D] = &&L_ALU_BIN; // sar

        dispatch[0x100 | 0x11] = &&L_CMP; // compara, no escribe
        dispatch[0x100 | 0x14] = &&L_MOV; // mov, y la variante de reg especial

        // ALU de tres operandos: nueve opcodes, UNA etiqueta.
        for (unsigned o = 0x73; o <= 0x7B; ++o) dispatch[0x100 | o] = &&L_ALU3;

        dispatch_ready = true;
    }
    goto *dispatch[idx];

L_ALU_BIN:
    form_alu_bin(d, out);
    goto L_DONE;
L_CMP:
    form_cmp(d, out);
    goto L_DONE;
L_MOV:
    form_mov(d, out);
    goto L_DONE;
L_ALU3:
    form_alu3(d, out);
    goto L_DONE;
L_UNDECLARED:
    if (fatal) fail_undeclared(v, ext, op);
    return false;
L_DONE:;
#else
/* No hay respaldo con `switch` a proposito: el `run_loop` de la VM ya exige
 * salto calculado, asi que pedirlo aqui no anade ninguna restriccion. */
#error "effects_decode necesita salto calculado (GCC/Clang)"
#endif

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

    /* Solo aqui se puede prometer exactitud, y solo si las DOS mitades la
     * tienen: la base derivada del codigo maquina y la forma declarada arriba. */
    out.exact = (v->effects & vm_isa::VE_EXACT) != 0 &&
                (v->effects & vm_isa::VE_IMPL) != 0;
    return true; // la forma esta declarada; la exactitud la dice `out.exact`
}

} // namespace

bool decode_effects(const DecodedInstr &d, InstrEffects &out) {
    // Sin forma declarada no vuelve de aqui, asi que el valor solo puede
    // hablar de la otra mitad: si lo que dice es completo.
    (void)decode_effects_impl(d, out, /*fatal=*/true);
    return out.exact;
}

bool probe_effects(const DecodedInstr &d, InstrEffects &out) {
    return decode_effects_impl(d, out, /*fatal=*/false);
}

} // namespace runtime
