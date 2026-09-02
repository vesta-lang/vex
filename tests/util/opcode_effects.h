/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/opcode_effects.h
 * @brief Que toca cada opcode de la VM: la FORMA y los EFECTOS IMPLICITOS.
 *
 * Para que
 * --------
 * Sin saber que toca cada instruccion no se puede afirmar que dos son
 * independientes, y sin eso no hay ni reordenacion dentro de un paquete ni
 * vectorizacion.  Es el prerrequisito de las dos tecnicas que faltan.
 *
 * Esta aqui, y no dentro de un test, porque lo necesitan DOS: el que saca la
 * tabla y la pagina de doc (`test_efectos_opcodes`) y el que mide cuanta
 * independencia real hay dentro de los paquetes (`test_bundle_ilp`).  Con una
 * copia en cada uno, la que no se toca se queda vieja en silencio.
 *
 * De donde sale cada mitad, y por que no del mismo sitio
 * -----------------------------------------------------
 *   - La FORMA (que registros nombra) tiene indice VARIABLE
 *     (`regs[instr.reg1]`), asi que solo el formato lo sabe -> la da el
 *     DESENSAMBLADOR, que es el unico que ya conocia el formato de los 232
 *     opcodes: no se puede imprimir `r3` sin saber de que campo sale.
 *   - Los EFECTOS IMPLICITOS (banderas, pila, marco, contador de programa)
 *     estan en offsets CONSTANTES de `ProcessVM` -> los ve el analisis del
 *     CODIGO MAQUINA del manejador.  Los offsets salen de `offsetof`, no a ojo.
 *
 * Nada de esto EJECUTA la instruccion.  Ejecutar con operandos inventados no
 * mide, adivina: el union de operandos tiene ocho interpretaciones de los
 * mismos 16 bytes y no hay relleno valido para todas a la vez -- salieron
 * divisiones por cero, `dlopen("")` y un opcode que pidio 18 GB de una vez.
 *
 * Lo que NO sabe
 * --------------
 * Una fila con `complete == false` es COTA INFERIOR: queda una llamada
 * indirecta que no se pudo seguir, asi que lo listado es cierto pero puede
 * haber mas.  Quien decida REORDENAR tiene que tratarla como barrera; darla por
 * completa es el fallo silencioso que este modelo existe para evitar.
 */

#ifndef VESTA_TESTS_OPCODE_EFFECTS_H
#define VESTA_TESTS_OPCODE_EFFECTS_H

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include <capstone/capstone.h>

#include "disasm/disasm.h"
#include "runtime/decode_instruction.h"
#include "runtime/decode_table.h"
#include "runtime/exec_instruction.h"
#include "runtime/exception_runtime.h"
#include "runtime/proceso_runtime.h"

#include "handler_walk.h"

namespace tests {

/* Bytes de operando de la instruccion de prueba.
 *
 * Cada byte lleva un par de nibbles DISTINTO: 0x21, 0x43, 0x65...  Todo nibble
 * es un indice de registro valido (0-15), y que sean distintos importa -- si
 * dos operandos cayeran en el mismo registro no se podria ver que son dos.
 * `xchg` salia como `=r1 =r1` con un patron uniforme, y con este sale `=r1
 * =r3`, que es lo que de verdad codifica. */
inline uint8_t operand_byte(size_t k) {
    const unsigned lo = static_cast<unsigned>((2 * k + 1) & 0x0F);
    const unsigned hi = static_cast<unsigned>((2 * k + 2) & 0x0F);
    return static_cast<uint8_t>((hi << 4) | lo);
}

/**
 * @brief Instrucciones que TRANSFIEREN CONTROL.
 *
 * No se reordenan nunca, toquen los registros que toquen: moverlas cambia que
 * se ejecuta despues.  Se marcan aparte porque sus operandos SI se derivan
 * igual que los demas -- lo que no se puede es moverlas.
 *
 * DERIVADA del codigo: son los manejadores que escriben `registers.rip` o
 * marcan `did_jump`.  La comparacion es por PUNTERO A FUNCION, no por indice de
 * opcode: un indice mal puesto es un fallo silencioso, y renombrar un manejador
 * con punteros es un error de compilacion.
 */
inline bool transfers_control(const runtime::InstrFormat &f) {
    const auto e = f.exec;
    return e == &runtime::exec_instr_callclosure ||
           e == &runtime::exec_instr_callitf ||
           e == &runtime::exec_instr_callm ||
           e == &runtime::exec_instr_callrawclosure ||
           e == &runtime::exec_instr_callsuper ||
           e == &runtime::exec_instr_callvirt ||
           e == &runtime::exec_instr_callvm ||
           e == &runtime::exec_instr_callvmr ||
           e == &runtime::exec_instr_cmpjmp ||
           e == &runtime::exec_instr_cmpjmpu ||
           e == &runtime::exec_instr_decjnz || e == &runtime::exec_instr_hlt ||
           e == &runtime::exec_instr_jmp || e == &runtime::exec_instr_jmpr ||
           e == &runtime::exec_instr_jrel ||
           e == &runtime::exec_instr_jumptable ||
           e == &runtime::exec_instr_loadmod ||
           e == &runtime::exec_instr_proceed || e == &runtime::exec_instr_ret ||
           e == &runtime::exec_instr_spawn ||
           e == &runtime::exec_instr_spawn_on ||
           e == &runtime::exec_instr_spawnargs ||
           e == &runtime::exec_instr_swapctx ||
           e == &runtime::exec_instr_tailcall ||
           e == &runtime::exec_instr_typeswitch;
}

/* ---------------------------------------------------------------------------
 * Efectos IMPLICITOS: los que no aparecen como operando.
 *
 *     cmp r1, r2   no escribe ningun registro... pero escribe las FLAGS
 *     jne destino  no lee ningun registro...    pero las LEE
 *     push r1      toca rsp sin nombrarlo
 *
 * Mirando solo los operandos, esas dos primeras parecen independientes, y
 * reordenarlas cambia el programa.  Sin esto no se puede decidir que se puede
 * mover dentro de un paquete.
 *
 * De donde salen: del CODIGO MAQUINA del manejador.  Es justo el reparto que
 * hace falta, y no es casual:
 *
 *   - la FORMA (que registro) tiene indice VARIABLE (`regs[instr.reg1]`), asi
 *     que solo el formato lo sabe -> la da el desensamblador;
 *   - los efectos implicitos estan en offsets CONSTANTES dentro de `ProcessVM`
 *     (`registers.flags`, `stack_pointer`...) -> los ve el analisis estatico.
 *
 * El offset se saca con `offsetof`, no a ojo: si alguien mueve un campo de
 * sitio, esto sigue mirando donde toca.
 * ------------------------------------------------------------------------- */

/// Un campo del proceso que interesa vigilar, con el rango que ocupa.
struct Field {
    const char *nombre;
    size_t ini, fin; ///< [ini, fin) dentro de `ProcessVM`
};

constexpr size_t kRegs = offsetof(runtime::ProcessVM, registers);

/// Donde empieza el BANCO de registros dentro del proceso.  Es el
/// desplazamiento con el que el manejador accede a `regs[campo]`, y lo que
/// distingue ese acceso de cualquier otro.
constexpr size_t kRegsOff =
    kRegs + offsetof(runtime::context_registers_vm, regs);

/// Lo que ocupa UN registro del banco.  Acota que desplazamientos, contados
/// desde el puntero que se le paso al ayudante, siguen siendo el mismo
/// registro: mas alla ya es el de al lado, y atribuirselo seria un error.
constexpr size_t kRegSize = sizeof(runtime::GeneralRegister);

/* Los campos, por offset.  `regs[]` va entero como un solo rango: un acceso con
 * indice variable cae en cualquier parte de el, y no se puede saber en cual sin
 * ejecutar -- para eso esta la forma, que sale del desensamblador. */
const Field kFields[] = {
    {"flags", kRegs + offsetof(runtime::context_registers_vm, flags),
     kRegs + offsetof(runtime::context_registers_vm, flags) +
         sizeof(((runtime::context_registers_vm *)nullptr)->flags)},
    {"pila", kRegs + offsetof(runtime::context_registers_vm, stack_pointer),
     kRegs + offsetof(runtime::context_registers_vm, stack_pointer) + 8},
    {"marco", kRegs + offsetof(runtime::context_registers_vm, base_pointer),
     kRegs + offsetof(runtime::context_registers_vm, base_pointer) + 8},
    {"pc", kRegs + offsetof(runtime::context_registers_vm, rip),
     kRegs + offsetof(runtime::context_registers_vm, rip) + 8},
};

/// Efectos observados en el codigo de un manejador.
struct ImplicitEffects {
    uint32_t escribe = 0; ///< bit i = escribe kFields[i]
    uint32_t lee = 0;     ///< bit i = lee kFields[i]
    bool completo =
        true;            ///< false: habia llamadas indirectas, esto es una cota
    /// Donde se quedo el recorrido cuando no fue completo.  Sin esto, "no se
    /// sabe" no es accionable: no dice QUE cerrar.
    std::vector<std::string> sin_resolver;

    /* --- La FORMA, derivada -------------------------------------------------
     *
     * Que campos del operando indexan un acceso al banco de registros, y en que
     * direccion.  Un bit por (campo, parte):
     *
     *     0: reg1 entero    1: reg1 nibble bajo   2: reg1 nibble alto
     *     3: reg2 entero    4: reg2 nibble bajo   5: reg2 nibble alto
     *
     * Sale del mismo recorrido que los efectos: el manejador hace
     * `regs[campo]`, que en codigo maquina es un acceso con el banco de
     * desplazamiento y el campo de indice.  La procedencia (`Origin`) dice CUAL
     * de los dos campos lleva ese indice, que es lo que no se podia saber antes.
     *
     * Si sale 0 no significa "no toca registros": significa que el recorrido no
     * lo vio, y hay que tratarlo como desconocido igual que los efectos. */
    uint8_t form_read = 0;
    uint8_t form_write = 0;
    /// Accesos que caen en el banco pero cuyo campo NO se pudo identificar.
    /// Sin esto, "forma vacia" no distingue "no toca registros" de "no se supo
    /// de cual", que son cosas distintas y llevan a arreglos distintos.
    uint32_t form_unknown = 0;
    /// El primero de ellos, para poder mirarlo.
    std::string form_why;
    /// Instrucciones que la base del compilador NO supo emparejar.  Cada una es
    /// un hueco de la base, y quien lea esto debe FALLAR, no seguir: taparlo con
    /// un valor conservador es lo que hizo que `lea` estuviera sin modelar sin
    /// que nadie lo notara.
    std::set<std::string> unmodeled;
    /// Accesos que caen en el rango de un campo vigilado pero cuya base NO se
    /// pudo situar en nuestra estructura.  No se atribuyen -- serian efectos
    /// inventados -- pero se cuentan: cada uno es procedencia que el recorrido
    /// perdio, y cerrarlos hace el resultado mas fino, no mas correcto.
    uint32_t ajenos = 0;
    std::string ajeno_why; ///< el primero, para poder mirarlo
    /**
     * @brief El manejador puede ABORTAR: llega a `throw_fatal`.
     *
     * No es un efecto mas, es lo que hace innecesarios a varios.  `mod` divide,
     * y dividir por cero llama a `throw_fatal(vm, ...)` -- con el proceso como
     * primer argumento, o sea con procedencia legitima --.  A partir de ahi el
     * recorrido entra en la traza de pila, el formateo del mensaje y el runtime
     * de C++, y le atribuia a `mod` todo lo que toca el camino de FALLO: salia
     * que escribe la pila, el marco y el contador de programa.
     *
     * No los escribe `mod`: los escribe LANZAR.  Y para lo que esto sirve --
     * decidir que se puede mover -- un opcode que puede abortar es una BARRERA,
     * que es mas fuerte que esos cuatro efectos y ademas cierto.  Asi que el
     * recorrido se para ahi y lo apunta, en vez de seguir y contar lo ajeno.
     */
    bool can_abort = false;
    uint32_t tablas = 0; ///< despachos por tabla que se pudieron seguir
    /* La instruccion CONCRETA que produjo cada efecto, una por campo y por
     * direccion.
     *
     * El criterio es el desplazamiento, y el desplazamiento se puede parecer al
     * de otra estructura cualquiera.  Sin poder mirar QUE instruccion lo dijo,
     * un falso positivo y un efecto real son indistinguibles -- que es como
     * `mov` acabo declarando que escribe las banderas cuando su propio codigo
     * dice "MOV no modifica ningun flag". */
    std::string prueba_w[4]; ///< la que escribe
    std::string prueba_r[4]; ///< la que lee
};

/**
 * @brief Que campos constantes del proceso toca este manejador.
 *
 * Se mira el DESPLAZAMIENTO de cada acceso a memoria.  No se sigue de donde
 * sale el registro base -- eso seria analisis de flujo de datos --, pero los
 * desplazamientos son lo bastante distintivos como para que un falso positivo
 * sea improbable: son offsets concretos de una estructura de miles de bytes.
 *
 * Ante la duda marca el efecto.  Para decidir reordenaciones, sobrar un efecto
 * impide una optimizacion; faltar uno rompe el programa.
 */
/**
 * @brief De que campo del operando salio un indice, segun NUESTRA codificacion.
 *
 * El idioma de la ISA dice "este registro lleva los bits [shift, shift+width) de
 * lo que se leyo en tal desplazamiento del segundo argumento".  Traducir eso a
 * "el primer operando" o "el nibble alto del segundo" es cosa de aqui, que es
 * quien conoce el formato: dos campos de registro de CUATRO bits metidos en un
 * byte, uno en cada nibble.
 *
 * Es el reparto que hace que anadir otra arquitectura no obligue a repetir el
 * formato de la VM en sus idiomas.
 *
 * @return El bit de `form_read`/`form_write`, o 0 si no es un campo conocido.
 */
inline uint8_t operand_field_bit(const tests::Origin &o) {
    if (!o.valid || o.base != 1) return 0; // el 2o argumento es la instruccion

    /* Cual de los dos campos, por su desplazamiento dentro de `DecodedInstr`. */
    const size_t off_reg1 =
        offsetof(runtime::DecodedInstr, data_instruction.reg_data.reg1);
    const size_t off_reg2 =
        offsetof(runtime::DecodedInstr, data_instruction.reg_data.reg2);
    int field;
    if (static_cast<size_t>(o.disp) == off_reg1)
        field = 0;
    else if (static_cast<size_t>(o.disp) == off_reg2)
        field = 1;
    else
        return 0;

    /* Y que parte de el.  Un campo de registro son CUATRO bits; el byte entero
     * es el valor directo (convencion A) y cada nibble es un campo distinto
     * (convencion B). */
    constexpr uint8_t kRegFieldBits = 4;
    int part;
    if (o.width >= 8 && o.shift == 0)
        part = 0; // el byte entero
    else if (o.width == kRegFieldBits && o.shift == 0)
        part = 1; // nibble bajo
    else if (o.width == kRegFieldBits && o.shift == kRegFieldBits)
        part = 2; // nibble alto
    else
        return 0; // un trozo que no es un campo: no se atribuye a ninguno

    return static_cast<uint8_t>(1u << (field * 3 + part));
}

/**
 * @brief Hasta donde se recorre: el camino de FALLO no es lo que hace el opcode.
 *
 * `throw_fatal` recibe el proceso como primer argumento, asi que llegar a el es
 * legitimo y todo lo que hay dentro tiene procedencia buena.  Pero lo que hay
 * dentro es la traza de pila, el formateo del mensaje y el runtime de C++, y
 * atribuirselo al opcode es decir que una division escribe la pila, el marco y
 * el contador de programa.  Los escribe LANZAR.
 *
 * Se para ahi y se apunta que el opcode PUEDE ABORTAR, que para decidir si algo
 * se puede mover es mas fuerte que esos cuatro efectos -- un opcode que aborta
 * es una barrera -- y ademas es cierto.
 *
 * Por PUNTERO A FUNCION, no por nombre: renombrar una es un error de
 * compilacion, y un nombre mal escrito seria un filtro que no filtra nada.
 */
inline const std::set<uint64_t> &fatal_frontier() {
    static const std::set<uint64_t> f = {
        reinterpret_cast<uint64_t>(
            reinterpret_cast<const void *>(&runtime::throw_fatal)),
        reinterpret_cast<uint64_t>(
            reinterpret_cast<const void *>(&runtime::throw_fatalf)),
    };
    return f;
}

inline ImplicitEffects implicit_effects_of(csh cs, const void *handler) {
    ImplicitEffects out;
    if (handler == nullptr) return out;

    tests::WalkResult res;
    std::set<WalkVisit> vistas;
    /* Las ultimas instrucciones vistas.  Un acceso al banco cuyo indice no se
     * identifica no se explica con la instruccion en si: se explica con lo que
     * cargo el indice, que esta ANTES.  Sin eso, el diagnostico dice que no se
     * supo pero no que hay que cerrar. */
    std::vector<std::string> previas;
    tests::walk_handler(
        cs, reinterpret_cast<uint64_t>(handler), 6, vistas,
        [&out, &previas](const cs_insn &in, const tests::TableState &st) {
            /* Los accesos a memoria, ya interpretados por el idioma de la ISA.
             * Aqui no se sabe que es un operando ni si el destino va primero:
             * eso cambia con la arquitectura y vive en `isa::mem_access`.  Lo
             * que si es del dominio son los DESPLAZAMIENTOS que interesan. */
            const int n_mem = tests::isa::mem_access_count(in);
            /* Se apunta ANTES de mirar los accesos para que, cuando uno no se
             * sepa explicar, lo que se guarde sea lo que vino antes de EL. */
            struct Apuntar {
                std::vector<std::string> &v;
                const cs_insn &i;
                ~Apuntar() {
                    char b[160];
                    std::snprintf(b, sizeof(b), "0x%llX: %s %s",
                                  (unsigned long long)i.address, i.mnemonic,
                                  i.op_str);
                    v.push_back(b);
                    if (v.size() > 5) v.erase(v.begin());
                }
            } apuntar{previas, in};
            for (int a = 0; a < n_mem; ++a) {
                const tests::isa::MemAccess acc = tests::isa::mem_access(in, a);

                /* Un campo de `ProcessVM` NUNCA se alcanza por la pila: el
                 * manejador recibe un PUNTERO, y el objeto vive en el monton.
                 * Por la pila solo se llega a las variables locales de la propia
                 * funcion, y por el contador de programa a las globales.
                 *
                 * Sin este filtro el criterio es solo el desplazamiento, y los
                 * campos vigilados caen en [0x40, 0x60) -- justo el rango de los
                 * marcos de pila corrientes --, asi que cualquier
                 * `mov [rsp+0x58], rax` se contaba como "escribe flags".  De ahi
                 * salia que `mov` escribiera las banderas y que `not` no las
                 * escribiera pero tocase el contador de programa.
                 *
                 * Si el compilador guarda el puntero en la pila, lo que hace por
                 * ahi es LEER EL PUNTERO; el acceso al campo sigue siendo por el
                 * registro donde lo deja, y ese si se mira. */
                if (acc.via_stack) continue;
                const bool escribe = acc.writes;
                const bool lee = acc.reads;

                /* --- La FORMA: un acceso al BANCO de registros --------------
                 *
                 * Va ANTES del filtro de desplazamiento porque el caso mas
                 * comun tiene desplazamiento CERO: el manejador calcula
                 * `&regs[campo]` y se lo pasa al ayudante, que accede por `[reg]`
                 * a secas.
                 *
                 * Dos formas de llegar, y las dos hacen falta:
                 *
                 *  1. El manejador toca el banco el mismo: el acceso lleva el
                 *     banco de desplazamiento y el campo de indice.
                 *  2. El ayudante lo toca por un puntero que le pasaron: el
                 *     desplazamiento y el indice viajaron en la semilla de la
                 *     llamada, y aqui solo queda un `[reg]`.
                 *
                 * En los dos casos se exige que la base salga del PRIMER
                 * argumento -- el proceso --: el mismo desplazamiento sobre otra
                 * estructura no es el banco. */
                if (acc.base >= 0 && !acc.address_only) {
                    const tests::AddrOrigin &a = st.addr[acc.base];
                    const bool caso1 =
                        acc.disp == static_cast<int64_t>(kRegsOff) &&
                        acc.index >= 0 && st.arg[acc.base] == 0;
                    const bool caso2 =
                        a.valid && a.base == 0 &&
                        a.disp == static_cast<int64_t>(kRegsOff) &&
                        acc.disp >= 0 &&
                        static_cast<size_t>(acc.disp) < kRegSize;
                    uint8_t bit = 0;
                    if (caso1)
                        bit = operand_field_bit(st.origin[acc.index]);
                    else if (caso2)
                        bit = operand_field_bit(a.index);
                    if (bit != 0) {
                        if (escribe) out.form_write |= bit;
                        if (lee) out.form_read |= bit;
                    } else if (caso1 || caso2) {
                        /* Se llego al banco pero no se supo a que campo.  Es
                         * distinto de no tocarlo, y se cuenta aparte. */
                        ++out.form_unknown;
                        if (out.form_why.empty()) {
                            const tests::Origin &o =
                                caso1 ? st.origin[acc.index] : a.index;
                            char buf[220];
                            std::snprintf(
                                buf, sizeof(buf),
                                "0x%llX: %s %s  (caso %d, indice base=%d "
                                "disp=%lld shift=%u width=%u valid=%d)",
                                (unsigned long long)in.address, in.mnemonic,
                                in.op_str, caso1 ? 1 : 2, o.base,
                                (long long)o.disp, o.shift, o.width,
                                o.valid ? 1 : 0);
                            out.form_why = buf;
                            /* Y lo de antes, que es donde esta la respuesta. */
                            for (const std::string &p : previas)
                                out.form_why += "\n           " + p;
                        }
                    }
                }

                if (acc.disp <= 0) continue;
                const size_t d = static_cast<size_t>(acc.disp);

                /* --- Y que sea NUESTRA estructura ---------------------------
                 *
                 * El desplazamiento SOLO no basta.  `mod` divide, dividir por
                 * cero lanza, y lanzar arrastra el runtime de C++ entero; ahi
                 * dentro hay estructuras con campos en 0x40, 0x48, 0x50 y 0x58
                 * como las hay en cualquier sitio.  Con el desplazamiento como
                 * unico criterio, `mod` declaraba escribir la pila, el marco y
                 * el contador de programa -- y hasta un `mov [rcx+0x42], ss`,
                 * que es codigo del sistema, contaba como tocar la pila.
                 *
                 * Sobrar efectos no da un resultado incorrecto, pero impide
                 * TODAS las reordenaciones alrededor, que es justo lo que se
                 * quiere habilitar.  Un efecto de mas es una optimizacion de
                 * menos.
                 *
                 * Se exige que la base venga del PRIMER argumento del
                 * manejador -- el proceso --, siguiendolo a traves de las
                 * llamadas con la semilla.  Lo que no se pueda situar se cuenta
                 * aparte: no se atribuye, pero tampoco se pierde. */
                const bool del_proceso =
                    acc.base >= 0 &&
                    (st.arg[acc.base] == 0 ||
                     (st.addr[acc.base].valid && st.addr[acc.base].base == 0));

                for (size_t k = 0; k < sizeof(kFields) / sizeof(kFields[0]);
                     ++k) {
                    if (d < kFields[k].ini || d >= kFields[k].fin) continue;
                    if (!del_proceso) {
                        /* Cae en el rango de un campo pero no se pudo situar en
                         * nuestra estructura.
                         *
                         * NO se descarta, y la razon es la que manda aqui:
                         * descartarlo QUITA efectos reales.  Se probo -- exigir
                         * procedencia le quita a `push` la escritura de la pila
                         * y a la ALU las banderas, porque la escritura vive en
                         * un ayudante compartido al que el rastro no llega --.
                         * Y sobrar un efecto cuesta una optimizacion, mientras
                         * que faltar uno rompe el programa.
                         *
                         * Se atribuye, pues, y se CUENTA aparte.  Cada uno es o
                         * bien procedencia que el recorrido perdio, o bien un
                         * efecto que no es nuestro -- `mod` divide, dividir por
                         * cero lanza, y ahi dentro hay estructuras con campos en
                         * los mismos desplazamientos --.  Hasta poder
                         * distinguirlos, se dice cuantos hay en vez de elegir
                         * en silencio. */
                        ++out.ajenos;
                        if (out.ajeno_why.empty()) {
                            char b[180];
                            std::snprintf(b, sizeof(b),
                                          "0x%llX: %s %s  (campo %s, base sin "
                                          "procedencia)",
                                          (unsigned long long)in.address,
                                          in.mnemonic, in.op_str,
                                          kFields[k].nombre);
                            out.ajeno_why = b;
                        }
                    }
                    if (escribe) out.escribe |= (1u << k);
                    if (lee) out.lee |= (1u << k);
                    // La primera instruccion de cada clase, para poder mirarla.
                    char buf[160];
                    std::snprintf(buf, sizeof(buf), "0x%llX: %s %s",
                                  (unsigned long long)in.address, in.mnemonic,
                                  in.op_str);
                    if (escribe && out.prueba_w[k].empty())
                        out.prueba_w[k] = buf;
                    if (lee && out.prueba_r[k].empty()) out.prueba_r[k] = buf;
                }
            }
        },
        res, tests::CallSeed{}, fatal_frontier());
    out.completo = res.completo();
    out.sin_resolver = res.unresolved;
    out.tablas = res.tables_resolved;
    out.unmodeled = res.unmodeled;
    out.can_abort = !res.fronteras.empty();
    return out;
}

struct OpcodeRow {
    std::string nombre;
    const char *tabla;
    int indice;
    std::string operandos; ///< texto del desensamblador, tal cual
    std::string modo;      ///< REG / MEM / SIB / INMED / NONE
    size_t bytes = 0;      ///< tamano de la instruccion
    std::vector<disasm::RegOperand> regs;
    bool salta = false;        ///< transfiere control: no se reordena nunca
    bool implementada = false; ///< tiene exec y decode
    ImplicitEffects imp;            ///< efectos que no son operandos
};

/**
 * @brief Construye el modelo de los 242 opcodes con nombre.
 *
 * Abre y cierra su propio Capstone, con el DETALLE activado: sin
 * `CS_OPT_DETAIL` las instrucciones vienen sin operandos y no se puede ver a
 * que campo del proceso accede cada una, que es justo lo que se busca.
 *
 * @param from Indice global desde el que empezar (0..255 primaria,
 *             256..511 extendida).  Sirve para acotar al depurar.
 */
inline std::vector<OpcodeRow> build_opcode_model(int from = 0) {
    struct {
        runtime::InstrFormat *t;
        const char *nom;
    } tablas[] = {
        {runtime::decode_table_primary, "primary"},
        {runtime::decode_table_extended, "extended"},
    };

    csh cs = 0;
    const bool hay_cs = (cs_open(kWalkArch, kWalkMode, &cs) == CS_ERR_OK);
    if (hay_cs) cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    std::vector<OpcodeRow> rows;
    for (auto &tb : tablas) {
        const bool primaria = (tb.nom[0] == 'p');
        const int base_tabla = primaria ? 0 : 0x100;
        for (int idx = 0; idx < 0x100; ++idx) {
            if (base_tabla + idx < from) continue;
            const runtime::InstrFormat &fmt = tb.t[idx];
            /* Basta con que la ranura tenga NOMBRE.  Antes se exigia tambien
             * `exec`, y por eso las ranuras reservadas sin implementar
             * --`edmw4`, `edmw6`, `loop`, `nop1`, `nop2`-- no salian, pese a
             * que la cabecera de la pagina generada prometia listarlas con la
             * nota "sin impl.".  La tabla dice que existen; que la VM las
             * rechace es un dato de la fila, no motivo para esconderla. */
            if (fmt.name == nullptr || !fmt.name[0]) continue;

            /* Una instruccion de este opcode, y se desensambla.  `disasm_bytes`
             * trabaja sobre un buffer: no hace falta VM, ni proceso, ni
             * fichero, y no se ejecuta nada. */
            uint8_t bytes[24];
            for (size_t k = 0; k < sizeof(bytes); ++k)
                bytes[k] = operand_byte(k);
            if (primaria) {
                bytes[0] = static_cast<uint8_t>(idx);
            } else {
                bytes[0] = 0x00; // prefijo de tabla extendida
                bytes[1] = static_cast<uint8_t>(idx);
            }

            disasm::DisasmOptions opts;
            opts.show_hex = false;
            opts.use_color = false;
            opts.stop_at_hlt = false;
            opts.max_bytes = sizeof(bytes);
            const auto res =
                disasm::disasm_bytes(bytes, sizeof(bytes), 0, opts);

            OpcodeRow f;
            f.nombre = fmt.name;
            f.tabla = tb.nom;
            f.indice = idx;
            f.salta = transfers_control(fmt);
            f.modo = Assembly::Bytecode::AddressingMode_str(fmt.mode);
            f.implementada = (fmt.exec != nullptr && fmt.decode != nullptr);
            /* Sin `decode` no hay nada que desensamblar: la forma se queda en
             * blanco y la fila vale solo para decir que la ranura existe. */
            if (!res.empty()) {
                f.operandos = res[0].operands;
                f.regs = res[0].regs;
                f.bytes = res[0].size;
            }
            if (hay_cs && fmt.exec != nullptr)
                f.imp = implicit_effects_of(
                    cs, reinterpret_cast<const void *>(fmt.exec));
            rows.push_back(f);
        }
    }
    if (hay_cs) cs_close(&cs);
    return rows;
}

} // namespace tests

#endif // VESTA_TESTS_OPCODE_EFFECTS_H
