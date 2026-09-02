/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/handler_walk.h
 * @brief Recorrer el CODIGO MAQUINA de un manejador, siguiendo sus llamadas.
 *
 * Por que existe
 * --------------
 * Dos derivaciones distintas necesitan lo mismo: recorrer lo que un
 * `exec_instr_*` ejecuta de verdad.
 *
 *   - `test_coste_opcodes` cuenta instrucciones para estimar el coste.
 *   - `test_efectos_opcodes` busca los EFECTOS IMPLICITOS: que un opcode toque
 *     las flags, la pila o el monton sin nombrarlos en ningun operando.
 *
 * Estaba solo en el primero.  Esta aqui para que el segundo no lo copie.
 *
 * Por que sobre el codigo maquina y no sobre el fuente
 * ---------------------------------------------------
 * Se intento derivar los efectos con expresiones regulares sobre el `.cpp` y no
 * funciona, por un motivo de fondo: un regex no distingue una llamada de un
 * `if`.  Literalmente -- `if (...) {` casaba como definicion de funcion, `if`
 * acumulaba los efectos de todos los `if` del proyecto, y como casi todo
 * manejador tiene uno, salia que todas las instrucciones tocaban todo.  Cierto
 * y completamente inutil.
 *
 * Sobre el binario no hay ambiguedad: una llamada es una llamada, y el destino
 * es una direccion.  Es ademas la unica forma de ver los efectos que estan
 * DENTRO de un ayudante: las flags de las ALU no se ponen en `exec_instr_add`,
 * sino en `AddOp::flags`, al que se llega por una tabla de plantillas.
 *
 * Lo que NO puede hacer
 * ---------------------
 * Un salto o una llamada INDIRECTA (por puntero de funcion, o el despacho por
 * tabla) no tiene destino visible, asi que lo que haya al otro lado no se
 * recorre.  Quien use esto tiene que enterarse: por eso el visitante recibe
 * tambien las llamadas que no se pudieron seguir, y puede decidir si el
 * resultado es exacto o solo una cota.
 */

#ifndef VESTA_TESTS_HANDLER_WALK_H
#define VESTA_TESTS_HANDLER_WALK_H

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <set>
#include <string>
#include <vector>

/* Para preguntarle al sistema si una direccion se puede leer y si es codigo.
 * Sin esa pregunta no se puede seguir una tabla de despacho: una base mal
 * rastreada acabaria desreferenciando cualquier cosa. */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cstdio>
#endif

#include <capstone/capstone.h>

namespace tests {

/**
 * @brief Que idioma de arquitectura hay escrito.
 *
 * Lo que se recorre es el codigo maquina del propio interprete, asi que la ISA
 * es la de la maquina donde se compilo: no hay eleccion posible ni nada que
 * decidir en ejecucion.
 *
 * Los idiomas viven mas abajo, en `namespace isa_x86`, y el alias `isa` elige
 * cual se usa.  Anadir ARM64 es escribir `namespace isa_arm64` con lo que dice
 * el contrato de aqui abajo; la logica del recorrido no se toca.
 *
 * El CONTRATO: que tiene que proveer un idioma
 * -------------------------------------------
 * Se escribe porque sin el, anadir una arquitectura es descubrir la superficie
 * a base de errores de compilacion, y cualquiera que amplie el recorredor la
 * agranda sin enterarse.  Todo esto vive DENTRO del namespace de la ISA:
 *
 *   Constantes    `kArch`, `kMode`      -- que abrir en Capstone
 *                 `kArgRegs`            -- cuantos argumentos van en registro
 *
 *   Tipos         `Origin`              -- que BITS de que campo lleva un
 *                                          registro.  Rango de bits, nunca
 *                                          "nibble": los campos son de la
 *                                          codificacion de la VM, no de la ISA
 *                 `AddrOrigin`          -- una direccion calculada y aun sin
 *                                          desreferenciar (lo que da un `lea`)
 *                 `TableState`          -- lo anterior por registro
 *                 `CallSeed`            -- lo que el llamante deja en los
 *                                          argumentos, para seguirlo al otro
 *                                          lado de la llamada
 *                 `MemAccess`           -- un acceso a memoria, con base,
 *                                          indice, desplazamiento y direccion
 *
 *   Funciones     `gpr_slot`            -- registro de la ISA -> ranura 0..15
 *                 `track_table_state`   -- que dice esta instruccion de los
 *                                          registros (procedencia, cotas,
 *                                          bases de tabla, direcciones)
 *                 `resolve_dispatch_table`, `read_dispatch_entries`,
 *                 `indirect_call_target` -- seguir un despacho indirecto
 *                 `mem_access_count`, `mem_access` -- los accesos a memoria
 *                 `seed_args`, `arg_slot`, `capture_call_seed`,
 *                 `apply_call_seed`     -- la convencion de llamada
 *                 `is_return`, `is_call`, `is_jump`, `is_tail_jump`,
 *                 `branch_target`       -- el flujo de control
 *
 * Lo que NO va en un idioma: cualquier constante de NUESTRA codificacion --
 * cuantos bits tiene un campo de registro, donde vive el banco, que campo es el
 * primer operando --.  Eso lo interpreta quien conoce el formato de la VM.
 *
 * Antes esto aceptaba ARM64 y seguia adelante leyendo `in.detail->x86`, que en
 * un binario ARM64 es basura: compilaba, corria y respondia mal -- el peor modo
 * de fallo posible, porque los efectos derivados alimentan decisiones de
 * reordenacion.  Mientras no esten escritos sus idiomas, no compilar es lo
 * unico honesto.
 */
#if defined(__x86_64__) || defined(_M_X64)
// Hay idiomas: `isa_x86`.
#elif defined(__aarch64__) || defined(_M_ARM64)
#error                                                                         \
    "el recorredor de manejadores solo tiene los idiomas de x86; ARM64 necesita los suyos (mapa de registros, despacho por tabla, destino, procedencia) -- antes esto compilaba y respondia mal"
#else
#error "ISA no soportada por el recorredor de manejadores"
#endif

/// Tope de bytes por funcion.  Red de seguridad: si no aparece el `ret` -- por
/// datos entre codigo, o por un salto que no se sigue -- se para aqui en vez de
/// leer memoria ajena.
constexpr size_t kWalkBytesMax = 128 * 1024;

/// Tope de instrucciones recorridas por manejador.  Se probo a subirlo a
/// 200.000 y NO cambio ni un opcode: la truncacion no era la causa de los
/// huecos, era un diagnostico mio que llamaba "truncado" a un salto indirecto
/// sin registrar.  Se deja donde estaba.
constexpr uint32_t kWalkInstrMax = 20000;

#if !defined(_WIN32)
/**
 * @brief Esta @p addr mapeada, y con permiso de ejecucion si @p need_exec?
 *
 * Equivalente de `VirtualQuery` leyendo `/proc/self/maps`, que es donde el
 * nucleo publica el mapa del proceso.  Se lee una sola vez: durante el analisis
 * no se carga nada, asi que el mapa no cambia.
 */
inline bool proc_maps_contains(uint64_t addr, bool need_exec) {
    struct Range {
        uint64_t lo, hi;
        bool exec;
    };
    static std::vector<Range> ranges = [] {
        std::vector<Range> v;
        std::FILE *f = std::fopen("/proc/self/maps", "r");
        if (f == nullptr) return v;
        char line[512];
        while (std::fgets(line, sizeof(line), f) != nullptr) {
            unsigned long long lo = 0, hi = 0;
            char perms[8] = {0};
            if (std::sscanf(line, "%llx-%llx %7s", &lo, &hi, perms) != 3)
                continue;
            if (perms[0] != 'r') continue; // ni siquiera se puede leer
            v.push_back({lo, hi, perms[2] == 'x'});
        }
        std::fclose(f);
        return v;
    }();
    for (const Range &r : ranges)
        if (addr >= r.lo && addr < r.hi) return !need_exec || r.exec;
    return false;
}
#endif

/* ---------------------------------------------------------------------------
 * Despacho por TABLA de punteros a funcion
 *
 * Es el hueco que dejaba fuera a la familia ALU entera.  El manejador no llama
 * al ayudante que hace el trabajo: lo saca de una tabla indexada por el ancho
 * del operando.  Compilado queda asi (`exec_instr_add_reg`, -O3):
 *
 *     lea    r10, [rip+0xdf9825]      ; <- la BASE de la tabla
 *     and    eax, 0x3                 ; <- cuantas entradas tiene: 4
 *     call   QWORD PTR [r10+rax*8]    ; <- la llamada que no se podia seguir
 *
 * Los dos datos que hacen falta estan EN EL CODIGO, no hay que suponerlos: la
 * `lea` relativa al contador de programa da la direccion de la tabla, y la
 * mascara del indice da su tamano.  Como la tabla vive en la parte de solo
 * lectura de ESTE MISMO binario -- lo que se analiza es el propio interprete --
 * se puede leer directamente y seguir cada entrada.
 *
 * Sin mascara no se resuelve nada.  Se podria leer "hasta que deje de parecer
 * codigo", pero eso es adivinar el tamano, y pasarse por arriba mete los
 * efectos de una funcion ajena.  Sin cota demostrable la llamada se sigue
 * contando como no seguida, y el resultado sigue siendo una cota inferior, que
 * es la respuesta honesta.
 *
 * Si la base rastreada fuese la equivocada -- el seguimiento es lineal y no
 * sabe de ramas -- lo que se lee no apunta a codigo ejecutable y se descarta.
 * En el peor caso se atribuyen efectos de mas, que es el lado seguro: sobrar un
 * efecto impide una optimizacion, faltar uno rompe el programa.
 * ------------------------------------------------------------------------- */

/// Tope de entradas por tabla.  Una mascara mayor no acota un indice de
/// despacho sino otra cosa que se le parece, y se descarta en vez de leer 64
/// KB.
constexpr uint64_t kWalkTableMax = 256;

/**
 * @brief Es @p addr codigo ejecutable de este proceso?
 *
 * Se le pregunta al SISTEMA, que es quien lo sabe, en vez de comparar contra un
 * rango supuesto.  Filtra dos cosas a la vez: que la direccion se pueda leer
 * --si no, el analisis moriria al desreferenciarla-- y que lo de dentro sea
 * codigo, porque una entrada que apunta a datos no es un manejador.
 */
inline bool is_code_addr(uint64_t addr) {
    if (addr == 0) return false;
#if defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD exec = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & exec) != 0;
#else
    return proc_maps_contains(addr, true);
#endif
}

/**
 * @brief Se puede LEER @p addr?  La misma pregunta, sin exigir que sea codigo.
 *
 * La tabla en si esta en la parte de solo lectura, no en la ejecutable, asi que
 * necesita su propia comprobacion.
 */
inline bool is_readable_addr(uint64_t addr) {
    if (addr == 0) return false;
#if defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & PAGE_NOACCESS) == 0 &&
           (mbi.Protect & PAGE_GUARD) == 0;
#else
    return proc_maps_contains(addr, false);
#endif
}

/* ===========================================================================
 * IDIOMAS DE x86
 *
 * Aqui empieza lo que es de UNA arquitectura y no del recorrido.  El recorrido
 * -- descodificar hasta el `ret`, seguir las llamadas, no repetir lo ya visto --
 * es el mismo en cualquier ISA; lo que cambia son los IDIOMAS: como se llama a
 * los registros, con que forma se despacha por tabla, cual de los operandos es
 * el destino, y como se ve que un valor salio de tal campo.
 *
 * Estan encerrados a proposito, no repartidos.  Anadir ARM64 es escribir
 * `namespace isa_arm64` con las mismas funciones y cambiar el alias de abajo;
 * la logica del recorredor no se toca.  Antes esto estaba suelto por todo el
 * fichero y ARM64 compilaba leyendo `in.detail->x86`, que en un binario ARM64
 * es basura: corria y respondia mal.
 *
 * Lo que un idioma tiene que dar esta abajo, en el alias `isa`.
 * ======================================================================== */
namespace isa_x86 {

/// La ISA y el modo con los que abrir Capstone.
constexpr cs_arch kArch = CS_ARCH_X86;
constexpr cs_mode kMode = CS_MODE_64;

/**
 * @brief Ranura 0..15 del registro entero de 64 bits que contiene a @p reg.
 *
 * La mascara se pone sobre `eax` y la llamada indexa con `rax`: son el mismo
 * registro, asi que hay que normalizar el ancho o el dato se pierde por el
 * camino.  Devuelve -1 para lo que no sea un registro entero de proposito
 * general.
 */
inline int gpr_slot(unsigned reg) {
    switch (reg) {
    case X86_REG_AL:
    case X86_REG_AH:
    case X86_REG_AX:
    case X86_REG_EAX:
    case X86_REG_RAX: return 0;
    case X86_REG_CL:
    case X86_REG_CH:
    case X86_REG_CX:
    case X86_REG_ECX:
    case X86_REG_RCX: return 1;
    case X86_REG_DL:
    case X86_REG_DH:
    case X86_REG_DX:
    case X86_REG_EDX:
    case X86_REG_RDX: return 2;
    case X86_REG_BL:
    case X86_REG_BH:
    case X86_REG_BX:
    case X86_REG_EBX:
    case X86_REG_RBX: return 3;
    case X86_REG_SPL:
    case X86_REG_SP:
    case X86_REG_ESP:
    case X86_REG_RSP: return 4;
    case X86_REG_BPL:
    case X86_REG_BP:
    case X86_REG_EBP:
    case X86_REG_RBP: return 5;
    case X86_REG_SIL:
    case X86_REG_SI:
    case X86_REG_ESI:
    case X86_REG_RSI: return 6;
    case X86_REG_DIL:
    case X86_REG_DI:
    case X86_REG_EDI:
    case X86_REG_RDI: return 7;
    case X86_REG_R8B:
    case X86_REG_R8W:
    case X86_REG_R8D:
    case X86_REG_R8: return 8;
    case X86_REG_R9B:
    case X86_REG_R9W:
    case X86_REG_R9D:
    case X86_REG_R9: return 9;
    case X86_REG_R10B:
    case X86_REG_R10W:
    case X86_REG_R10D:
    case X86_REG_R10: return 10;
    case X86_REG_R11B:
    case X86_REG_R11W:
    case X86_REG_R11D:
    case X86_REG_R11: return 11;
    case X86_REG_R12B:
    case X86_REG_R12W:
    case X86_REG_R12D:
    case X86_REG_R12: return 12;
    case X86_REG_R13B:
    case X86_REG_R13W:
    case X86_REG_R13D:
    case X86_REG_R13: return 13;
    case X86_REG_R14B:
    case X86_REG_R14W:
    case X86_REG_R14D:
    case X86_REG_R14: return 14;
    case X86_REG_R15B:
    case X86_REG_R15W:
    case X86_REG_R15D:
    case X86_REG_R15: return 15;
    default: return -1;
    }
}

/**
 * @brief De donde salio el valor de un registro, cuando se sabe.
 *
 * Sirve para responder "este indice, de que campo de la estructura vino?".  El
 * recorredor no sabe que es un campo ni que significa; se limita a apuntar
 * `[registro + desplazamiento]` y que transformacion se le aplico despues.
 * Interpretarlo es de quien conoce el dominio.
 *
 * Sin esto se ve que un manejador escribe `regs[algo]` pero no CUAL, que es
 * justo lo que hace falta para saber si el destino es el primer operando o el
 * segundo.
 */
struct Origin {
    int base = -1;    ///< argumento del que salio; -1 = no se sabe
    int64_t disp = 0; ///< desplazamiento dentro de ese argumento
    /* Que BITS de lo que se leyo lleva ahora el registro.
     *
     * Se guarda como rango de bits y no como "nibble bajo / nibble alto" a
     * proposito.  Un nibble es cosa de NUESTRA codificacion -- la convencion que
     * mete dos registros de cuatro bits en un byte --, no de la arquitectura, y
     * meterlo aqui obligaria a que cada ISA volviese a codificar el formato de
     * la VM en sus propios idiomas.
     *
     * El idioma dice "ahora lleva los bits [shift, shift+width)"; que eso sea el
     * primer o el segundo operando lo decide quien conoce la codificacion. */
    uint8_t shift = 0; ///< primer bit
    uint8_t width = 0; ///< cuantos bits; 0 = no se sabe
    bool valid = false;
};

/**
 * @brief Una DIRECCION que un registro lleva calculada, sin desreferenciar.
 *
 * Es lo que produce un `lea`: el registro no vale un dato, vale DONDE esta el
 * dato.  Hace falta porque los manejadores casi nunca tocan el banco de
 * registros ellos mismos -- calculan `&regs[campo]` y se lo pasan a un
 * ayudante, que es quien lee o escribe --.  Sin seguir la direccion a traves de
 * la llamada, lo unico que se ve es un `lea` sin destino, y la pregunta "que
 * campos usa este opcode" no tiene respuesta derivable.
 *
 * El indice se guarda con su procedencia entera: es lo que luego identifica
 * CUAL de los campos del operando indexa.
 */
struct AddrOrigin {
    int base = -1;     ///< argumento del que sale la base; -1 = no se sabe
    int64_t disp = 0;  ///< desplazamiento fijo dentro de el
    Origin index;      ///< de donde sale el indice, si lleva alguno
    uint8_t scale = 1; ///< escala del indice
    bool valid = false;
};

/// Lo que se sabe de los registros en este punto del recorrido.  Plano y de
/// tamano fijo: son 16 ranuras, no hace falta un mapa.
struct TableState {
    uint64_t base[16] = {}; ///< tabla cargada con `lea`/`mov` (0 = nada)
    int64_t mask[16] = {};  ///< mascara aplicada al registro (0 = nada)
    /// De donde salio lo que lleva cada registro.  Ver `Origin`.
    Origin origin[16];
    /// Direcciones calculadas y aun no desreferenciadas.  Ver `AddrOrigin`.
    AddrOrigin addr[16];
    /// Registros que llevan un argumento de la funcion, sin transformar.  Se
    /// siembra al entrar (la convencion fija cual es cual) y se propaga por las
    /// copias.  -1 = ninguno.
    int arg[16] = {-1, -1, -1, -1, -1, -1, -1, -1,
                   -1, -1, -1, -1, -1, -1, -1, -1};
    /* Punteros que el registro puede contener por haberse LEIDO de una tabla ya
     * resuelta.  Hace falta porque el despacho no siempre llama a traves de la
     * memoria: las variantes con inmediato de la ALU cargan la entrada y saltan
     * (`mov rax, [tabla+idx*8]` + `jmp rax`), que es una llamada de cola. */
    /* Cota a medias: un `cmp REG, imm` solo acota si detras va la rama que se
     * va cuando NO cabe.  Se apunta aqui y se confirma con la instruccion
     * siguiente; sola no vale de nada. */
    int pending_cmp_reg = -1;
    int64_t pending_cmp_imm = 0;
    std::vector<uint64_t> loaded[16];
};

/**
 * @brief Lee las entradas de la tabla que direcciona @p mem, si es una.
 *
 * Comun a los dos patrones de despacho --llamar a traves de la memoria y
 * cargar-y-saltar--, para que la condicion de "esto es una tabla" sea UNA y no
 * dos que se separen con el tiempo.
 *
 * @return Cuantas entradas se leyeron; 0 si no hay base, no hay cota, o lo
 *         leido no apunta a codigo.
 */
inline uint32_t read_dispatch_entries(const cs_x86_op &mem,
                                      const TableState &st,
                                      std::vector<uint64_t> &out,
                                      bool relative = false) {
    const int b = gpr_slot(mem.mem.base);
    const int k = gpr_slot(mem.mem.index);
    if (b < 0 || k < 0) return 0;
    const uint64_t base = st.base[b];
    const int64_t mask = st.mask[k];
    // Sin base no hay donde mirar; sin cota no hay tamano demostrable.
    if (base == 0 || mask <= 0) return 0;
    const uint64_t count = static_cast<uint64_t>(mask) + 1;
    if (count > kWalkTableMax) return 0;
    const uint64_t scale = mem.mem.scale > 0
                               ? static_cast<uint64_t>(mem.mem.scale)
                               : sizeof(uint64_t);
    const uint64_t table = base + static_cast<uint64_t>(mem.mem.disp);
    if (!is_readable_addr(table) ||
        !is_readable_addr(table + count * scale - 1))
        return 0;
    uint32_t done = 0;
    for (uint64_t e = 0; e < count; ++e) {
        uint64_t target = 0;
        if (relative) {
            /* Tabla de `switch`: las entradas son desplazamientos de 32 bits
             * CON SIGNO relativos a la propia tabla, no punteros.  Es lo que
             * emite el compilador para un `switch` denso, y es la forma que
             * usa toda la familia ALU de tres operandos. */
            int32_t delta = 0;
            std::memcpy(&delta,
                        reinterpret_cast<const void *>(table + e * scale),
                        sizeof(delta));
            target = table + static_cast<uint64_t>(static_cast<int64_t>(delta));
        } else {
            std::memcpy(&target,
                        reinterpret_cast<const void *>(table + e * scale),
                        sizeof(target));
        }
        // Una entrada que no apunta a codigo delata que la base rastreada no
        // era la de esta tabla: se descarta en vez de seguirla.
        if (!is_code_addr(target)) continue;
        out.push_back(target);
        ++done;
    }
    return done;
}

/**
 * @brief Actualiza @p st con lo que esta instruccion dice de los registros.
 *
 * Reconoce los patrones que producen una base de tabla, el que produce una
 * cota, y el que carga una entrada ya resuelta.  Cualquier otra escritura sobre
 * un registro OLVIDA lo que se sabia de el: un dato viejo aplicado a un valor
 * nuevo es justo el fallo silencioso que hay que evitar.
 */
inline void track_table_state(csh cs, const cs_insn &in, TableState &st) {
    if (in.detail == nullptr) return;
    const cs_x86 &x = in.detail->x86;
    const std::string m = in.mnemonic;
    /* La cota de un `switch`: `cmp REG, imm` + la rama que se va cuando NO
     * cabe.  El `cmp` SOLO no acota nada -- podria ser cualquier comparacion --,
     * asi que se apunta y se confirma con la instruccion siguiente.  Como el
     * recorrido sigue el camino de NO SALTO, ahi el valor si esta acotado.
     *
     * Es la segunda forma de acotar, y sin ella se quedaba fuera toda la
     * familia ALU de tres operandos, que era el 82% del peso de ejecucion. */
    const int prev_cmp_reg = st.pending_cmp_reg;
    const int64_t prev_cmp_imm = st.pending_cmp_imm;
    st.pending_cmp_reg = -1;

    if (m == "cmp" && x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_IMM) {
        const int d = gpr_slot(x.operands[0].reg);
        if (d >= 0 && x.operands[1].imm >= 0) {
            st.pending_cmp_reg = d;
            st.pending_cmp_imm = x.operands[1].imm;
        }
        return;
    }
    if (prev_cmp_reg >= 0) {
        /* `ja`/`jg` se van cuando es MAYOR, asi que al caer vale <= imm: imm+1
         * valores.  `jae`/`jge` se van cuando es mayor o IGUAL, asi que al caer
         * vale < imm: imm valores.  La cota se guarda como "el mayor indice
         * valido", que es lo que `read_dispatch_entries` suma uno. */
        if (m == "ja" || m == "jnbe" || m == "jg" || m == "jnle") {
            st.mask[prev_cmp_reg] = prev_cmp_imm;
            st.base[prev_cmp_reg] = 0;
            st.loaded[prev_cmp_reg].clear();
            return;
        }
        if (m == "jae" || m == "jnb" || m == "jge" || m == "jnl") {
            if (prev_cmp_imm > 0) {
                st.mask[prev_cmp_reg] = prev_cmp_imm - 1;
                st.base[prev_cmp_reg] = 0;
                st.loaded[prev_cmp_reg].clear();
            }
            return;
        }
    }


    /* --- Procedencia: de que campo salio lo que lleva un registro ---------
     *
     * Va ANTES de lo demas porque son los mismos mnemonicos: un
     * `movzx eax, BYTE PTR [rdx+0x8]` es a la vez "una carga cualquiera" para
     * el seguimiento de tablas y "el primer operando" para la procedencia.
     * Apuntarlo aqui no estorba a lo otro, que solo mira `lea`, `mov` de
     * inmediato y `and`. */
    if ((m == "movzx" || m == "movsx" || m == "mov") && x.op_count == 2 &&
        x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_MEM &&
        x.operands[1].mem.index == X86_REG_INVALID &&
        x.operands[1].mem.base != X86_REG_RIP) {
        const int d = gpr_slot(x.operands[0].reg);
        const int b = gpr_slot(x.operands[1].mem.base);
        if (d >= 0) {
            st.origin[d] = Origin{};
            st.arg[d] = -1;
            if (b >= 0 && st.arg[b] >= 0) {
                st.origin[d].base = st.arg[b];
                st.origin[d].disp = x.operands[1].mem.disp;
                st.origin[d].shift = 0;
                /* Los bits que trae la carga.  Capstone da el tamano del
                 * operando en bytes; se convierte a bits porque el rango es lo
                 * que el dominio va a interpretar. */
                st.origin[d].width =
                    static_cast<uint8_t>(x.operands[1].size * 8);
                st.origin[d].valid = true;
                /* Y se sale AQUI.  Sin esto, un `movzx eax, byte ptr [rdx+8]`
                 * -- la forma normal de leer un campo de un byte -- apuntaba su
                 * procedencia y acto seguido caia en la invalidacion final, que
                 * la borraba por ver que la instruccion escribe `eax`.  El
                 * resultado era que la procedencia funcionaba para `mov` (que
                 * sale antes por la rama de tablas) y NUNCA para `movzx`, que es
                 * justo la que carga los campos de registro.
                 *
                 * Salir no se lleva por delante el despacho por tabla: esa rama
                 * necesita un INDICE, y esta exige no tenerlo. */
                st.base[d] = 0;
                st.mask[d] = 0;
                st.loaded[d].clear();
                st.addr[d] = AddrOrigin{};
                return;
            }
        }
    }
    /* Extraer un trozo de bits.  Lo que se apunta es el RANGO, no "el nibble
     * bajo": cuantos bits caben en un campo es cosa de la codificacion de la VM,
     * no de x86, y ponerlo aqui obligaria a cada ISA a repetirlo.
     *
     * `and REG, mask` con una mascara de bits bajos contiguos deja `n` bits.
     * `shr REG, k` corre el rango k bits hacia arriba. */
    if (m == "and" && x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_IMM && x.operands[1].imm > 0) {
        const int d = gpr_slot(x.operands[0].reg);
        const uint64_t mask = static_cast<uint64_t>(x.operands[1].imm);
        // Mascara de bits bajos contiguos: `mask + 1` es potencia de dos.
        if (d >= 0 && st.origin[d].valid && (mask & (mask + 1)) == 0) {
            uint8_t n = 0;
            while ((mask >> n) != 0) ++n;
            if (n < st.origin[d].width) st.origin[d].width = n;
        }
    }
    if ((m == "shr" || m == "sar") && x.op_count == 2 &&
        x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_IMM &&
        x.operands[1].imm > 0 && x.operands[1].imm < 64) {
        const int d = gpr_slot(x.operands[0].reg);
        const uint8_t k = static_cast<uint8_t>(x.operands[1].imm);
        if (d >= 0 && st.origin[d].valid) {
            if (k < st.origin[d].width) {
                st.origin[d].shift = static_cast<uint8_t>(st.origin[d].shift + k);
                st.origin[d].width = static_cast<uint8_t>(st.origin[d].width - k);
            } else {
                st.origin[d] = Origin{}; // se lo llevo entero: ya no queda nada
            }
        }
    }

    // `lea REG, [rip+disp]`: la direccion absoluta ya es calculable aqui.
    if (m == "lea" && x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_MEM &&
        x.operands[1].mem.base == X86_REG_RIP &&
        x.operands[1].mem.index == X86_REG_INVALID) {
        const int d = gpr_slot(x.operands[0].reg);
        if (d >= 0) {
            st.base[d] = in.address + in.size + x.operands[1].mem.disp;
            st.mask[d] = 0;
            st.loaded[d].clear();
        }
        return;
    }
    /* `lea REG, [ARG + idx*escala + disp]`: una DIRECCION dentro de un
     * argumento, calculada y todavia sin desreferenciar.
     *
     * Es el paso que faltaba para poder derivar la forma.  Un manejador no
     * escribe `regs[campo]`: calcula su direccion y se la pasa a un ayudante.
     * Apuntando aqui de donde sale la direccion -- y con que indice --, la
     * semilla de la llamada la lleva al otro lado, y el acceso que el ayudante
     * hace por ese puntero se puede atribuir al campo correcto. */
    if (m == "lea" && x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_MEM &&
        x.operands[1].mem.base != X86_REG_RIP) {
        const int d = gpr_slot(x.operands[0].reg);
        const int b = gpr_slot(x.operands[1].mem.base);
        if (d >= 0) {
            AddrOrigin a;
            if (b >= 0 && st.arg[b] >= 0) {
                a.base = st.arg[b];
                a.disp = x.operands[1].mem.disp;
                a.scale = static_cast<uint8_t>(x.operands[1].mem.scale);
                const int idx = gpr_slot(x.operands[1].mem.index);
                if (idx >= 0) a.index = st.origin[idx];
                a.valid = true;
            } else if (b >= 0 && st.addr[b].valid &&
                       x.operands[1].mem.index == X86_REG_INVALID) {
                /* Sumar un desplazamiento a una direccion que ya se seguia:
                 * sigue siendo la misma region, un poco mas alla.  Es como se
                 * llega a un campo de la estructura que hay ahi. */
                a = st.addr[b];
                a.disp += x.operands[1].mem.disp;
            }
            st.addr[d] = a;
            /* Un `lea` no lee memoria, asi que el registro no lleva ningun
             * valor de ningun campo: solo una direccion. */
            st.origin[d] = Origin{};
            st.arg[d] = -1;
            st.base[d] = 0;
            st.mask[d] = 0;
            st.loaded[d].clear();
        }
        return;
    }
    // `mov REG, imm`: la misma base cuando el codigo no es relativo.
    if ((m == "mov" || m == "movabs") && x.op_count == 2 &&
        x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_IMM) {
        const int d = gpr_slot(x.operands[0].reg);
        if (d >= 0) {
            st.base[d] = static_cast<uint64_t>(x.operands[1].imm);
            st.mask[d] = 0;
            st.loaded[d].clear();
        }
        return;
    }
    /* `mov REG, [tabla + idx*8]` / `movsxd REG, [tabla + idx*4]`: se carga UNA
     * entrada, pero cual depende del indice, asi que el registro pasa a valer
     * cualquiera de las N.  Es la primera mitad de un salto de cola; la segunda
     * es el `jmp REG`.
     *
     * El `movsxd` con escala 4 es la tabla de un `switch`, cuyas entradas son
     * desplazamientos con signo relativos a la tabla; el `mov` de 8 bytes es
     * una tabla de punteros.  La diferencia esta en la propia instruccion, no
     * hay que suponerla. */
    if ((m == "mov" || m == "movsxd") && x.op_count == 2 &&
        x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_MEM) {
        const int d = gpr_slot(x.operands[0].reg);
        if (d >= 0) {
            std::vector<uint64_t> targets;
            read_dispatch_entries(x.operands[1], st, targets, m == "movsxd");
            st.base[d] = 0;
            st.mask[d] = 0;
            st.loaded[d] = std::move(targets);
        }
        return;
    }
    /* `add REG, BASE` justo despues de leer una tabla relativa: es el paso que
     * convierte el desplazamiento en direccion, y ya se hizo al leerla.  Sin
     * esta excepcion el `add` borraria los destinos una instruccion antes del
     * `jmp` que los usa. */
    if (m == "add" && x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_REG) {
        const int d = gpr_slot(x.operands[0].reg);
        const int s = gpr_slot(x.operands[1].reg);
        if (d >= 0 && s >= 0 && !st.loaded[d].empty() && st.base[s] != 0)
            return; // se conserva lo cargado
    }
    /* Copia entre registros: lo que se sabia del origen vale para el destino.
     *
     * Las EXTENSIONES DE ANCHO cuentan como copia, y no es un detalle: el
     * indice se acota con `and eax, 0x3` y luego se extiende con `cdqe` para
     * indexar con `rax`.  Como el valor ya esta en [0, 3], extenderlo no lo
     * cambia, asi que la cota sigue valiendo.  Tratando `cdqe` como una
     * escritura cualquiera se perdia la cota justo antes de usarla. */
    if ((m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd") &&
        x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_REG) {
        const int d = gpr_slot(x.operands[0].reg);
        const int s = gpr_slot(x.operands[1].reg);
        if (d >= 0 && s >= 0) {
            st.base[d] = st.base[s];
            st.mask[d] = st.mask[s];
            st.loaded[d] = st.loaded[s];
            // La procedencia, el argumento y la direccion viajan con el valor.
            st.origin[d] = st.origin[s];
            st.arg[d] = st.arg[s];
            st.addr[d] = st.addr[s];
        }
        return;
    }
    /* `cdqe`/`cwde`/`cbw` extienden el acumulador sobre si mismo: mismo valor,
     * mas ancho.  Se deja como estaba. */
    if (m == "cdqe" || m == "cwde" || m == "cbw") return;
    // `and REG, imm`: la cota del indice, que es lo que da el tamano.
    if (m == "and" && x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_IMM) {
        const int d = gpr_slot(x.operands[0].reg);
        if (d >= 0) {
            st.mask[d] = x.operands[1].imm;
            st.base[d] = 0;
            st.loaded[d].clear();
        }
        return;
    }

    // Cualquier otra escritura invalida lo que se sabia.  Se pregunta por los
    // registros que la instruccion escribe DE VERDAD, implicitos incluidos: un
    // `div` toca `rdx` sin nombrarlo en ningun operando.
    cs_regs read_regs, written_regs;
    uint8_t n_read = 0, n_written = 0;
    if (cs_regs_access(cs, &in, read_regs, &n_read, written_regs, &n_written) !=
        0)
        return;
    for (uint8_t i = 0; i < n_written; ++i) {
        const int d = gpr_slot(written_regs[i]);
        if (d >= 0) {
            st.base[d] = 0;
            st.mask[d] = 0;
            st.loaded[d].clear();
            /* La procedencia tambien se pierde.  Un registro que ya no lleva lo
             * que se leyo del campo no puede seguir diciendo que lo lleva: eso
             * atribuiria un acceso al operando equivocado, que es peor que no
             * atribuirlo a ninguno. */
            st.origin[d] = Origin{};
            st.arg[d] = -1;
            st.addr[d] = AddrOrigin{};
        }
    }
}


/**
 * @brief Destino de un `call qword ptr [rip + disp]`.
 *
 * Es la forma de llamar a una funcion de OTRO modulo: la direccion no esta en
 * la instruccion, esta en una ranura de la tabla de importaciones, y la ranura
 * SI tiene direccion fija.  Asi que se lee, igual que se lee una tabla de
 * despacho -- mismo principio, no hay nada que suponer.
 *
 * Cerrarlo importa: era el 208 de las renuncias del derivador.  Y lo que hay
 * al otro lado suele ser `memcpy` o una API del sistema, que no toca el
 * `ProcessVM`; seguirla y no encontrar efectos es la respuesta CORRECTA, muy
 * distinta de "no se sabe".
 *
 * @return La direccion, o 0 si no es esta forma o no apunta a codigo.
 */
inline uint64_t indirect_call_target(const cs_insn &in) {
    if (in.detail == nullptr) return 0;
    const cs_x86 &x = in.detail->x86;
    for (uint8_t i = 0; i < x.op_count; ++i) {
        const cs_x86_op &op = x.operands[i];
        if (op.type != X86_OP_MEM) continue;
        if (op.mem.base != X86_REG_RIP) continue;
        if (op.mem.index != X86_REG_INVALID) continue;
        const uint64_t slot =
            in.address + in.size + static_cast<uint64_t>(op.mem.disp);
        if (!is_readable_addr(slot) || !is_readable_addr(slot + 7)) return 0;
        uint64_t target = 0;
        std::memcpy(&target, reinterpret_cast<const void *>(slot),
                    sizeof(target));
        return is_code_addr(target) ? target : 0;
    }
    return 0;
}
/**
 * @brief Saca de @p in los destinos de un despacho por tabla, si lo es.
 *
 * Cubre los dos patrones: llamar o saltar a traves de la memoria, y saltar a un
 * registro cargado antes desde la tabla.
 *
 * @param in  La llamada o el salto indirecto.
 * @param st  Bases, cotas y punteros cargados conocidos en este punto.
 * @param out Se anaden los destinos resueltos.
 * @return Cuantos se resolvieron; 0 si no se pudo, y entonces la llamada sigue
 *         contando como no seguida.
 */
inline uint32_t resolve_dispatch_table(const cs_insn &in, const TableState &st,
                                       std::vector<uint64_t> &out) {
    if (in.detail == nullptr) return 0;
    const cs_x86 &x = in.detail->x86;
    for (uint8_t i = 0; i < x.op_count; ++i) {
        const cs_x86_op &op = x.operands[i];
        if (op.type == X86_OP_MEM) {
            const uint32_t n = read_dispatch_entries(op, st, out);
            if (n > 0) return n;
        } else if (op.type == X86_OP_REG) {
            // `jmp rax` tras `mov rax, [tabla+idx*8]`: los destinos ya se
            // leyeron cuando se cargo el registro.
            const int r = gpr_slot(op.reg);
            if (r >= 0 && !st.loaded[r].empty()) {
                for (uint64_t t : st.loaded[r])
                    out.push_back(t);
                return static_cast<uint32_t>(st.loaded[r].size());
            }
        }
    }
    return 0;
}

/* --- Lo que el recorrido pregunta de cada instruccion -------------------
 *
 * Cuatro preguntas, y las cuatro tienen respuesta distinta en cada ISA.  Estaban
 * escritas a mano dentro del bucle comparando mnemonicos; aqui tienen nombre,
 * que es lo que permite que otra arquitectura las conteste a su manera. */

/**
 * @brief Un acceso a memoria de una instruccion, ya interpretado.
 *
 * Es lo que hace falta para preguntar "toca este campo de la estructura?" sin
 * saber nada de x86.  Quien analiza el dominio conoce los desplazamientos que le
 * importan; que forma tiene un operando de memoria, y si se lee o se escribe, es
 * del idioma.
 */
struct MemAccess {
    int base = -1;      ///< ranura del registro base; -1 si no es un GPR
    int index = -1;     ///< ranura del indice; -1 si no lleva
    int64_t disp = 0;   ///< desplazamiento
    uint8_t scale = 1;  ///< escala del indice
    bool reads = false;
    bool writes = false;
    /**
     * @brief No es un acceso: es solo el CALCULO de una direccion.
     *
     * `reads`/`writes` van los dos a cierto en este caso, porque para saber si
     * un opcode toca una region es lo seguro: la direccion puede acabar en
     * cualquier sitio y hacer cualquier cosa.
     *
     * Pero para saber QUE campo se lee y cual se escribe eso es veneno --
     * atribuye las dos direcciones a la vez y sale que `add` lee y escribe el
     * mismo operando --.  Calcular una direccion no dice nada de la direccion
     * del acceso; eso lo dice quien la usa.  Por eso se distingue.
     */
    bool address_only = false;
    /**
     * @brief El acceso va por la pila, el marco o el contador de programa.
     *
     * Quien busca un campo de una estructura del monton tiene que descartarlos:
     * por ahi solo se llega a las variables locales de la propia funcion y a las
     * globales.  Sin este filtro el criterio se queda en el desplazamiento, y
     * cualquier `[rsp+0x58]` se confunde con el campo que viva en 0x58.
     */
    bool via_stack = false;
};

/// @return Cuantos operandos de memoria tiene @p in.
inline int mem_access_count(const cs_insn &in) {
    if (in.detail == nullptr) return 0;
    int n = 0;
    const cs_x86 &x = in.detail->x86;
    for (uint8_t i = 0; i < x.op_count; ++i)
        if (x.operands[i].type == X86_OP_MEM) ++n;
    return n;
}

/**
 * @brief El acceso a memoria numero @p k de @p in.
 *
 * La direccion NO sale de `op.access` de Capstone: se comprobo y marca como
 * ESCRITURA el operando FUENTE -- el veredicto "`cmp` escribe las banderas"
 * salia de un `movzx r11d, byte ptr [rcx+0x58]`, que es una lectura --.  Con esa
 * clasificacion "lee" y "escribe" significaban lo mismo, que es justo lo que hay
 * que distinguir: dos lecturas del mismo sitio conmutan, una lectura y una
 * escritura no.
 *
 * La FORMA de x86 si es de fiar: el destino es el primer operando.
 */
inline MemAccess mem_access(const cs_insn &in, int k) {
    MemAccess a;
    if (in.detail == nullptr) return a;
    const cs_x86 &x = in.detail->x86;
    int visto = 0;
    for (uint8_t i = 0; i < x.op_count; ++i) {
        const cs_x86_op &op = x.operands[i];
        if (op.type != X86_OP_MEM) continue;
        if (visto++ != k) continue;

        a.base = gpr_slot(op.mem.base);
        a.index = gpr_slot(op.mem.index);
        a.disp = op.mem.disp;
        a.scale = static_cast<uint8_t>(op.mem.scale > 0 ? op.mem.scale : 1);
        a.via_stack =
            (op.mem.base == X86_REG_RSP || op.mem.base == X86_REG_ESP ||
             op.mem.base == X86_REG_RBP || op.mem.base == X86_REG_EBP ||
             op.mem.base == X86_REG_RIP);

        const char *mn = in.mnemonic;
        if (std::strcmp(mn, "lea") == 0) {
            /* `lea` no accede: calcula una direccion.  Pero si la de un campo se
             * pasa a otro sitio, ese sitio puede leerlo y escribirlo, y puede
             * que no se llegue a recorrer.  Se marca lo peor de los dos, y se
             * deja dicho que era solo un calculo. */
            a.reads = a.writes = true;
            a.address_only = true;
        } else if (i == 0 && std::strcmp(mn, "cmp") != 0 &&
                   std::strcmp(mn, "test") != 0 &&
                   std::strcmp(mn, "push") != 0 &&
                   std::strcmp(mn, "call") != 0 && mn[0] != 'j') {
            // Destino: se escribe.  Y se lee tambien salvo que la instruccion se
            // limite a poner un valor encima.
            a.writes = true;
            a.reads = (std::strncmp(mn, "mov", 3) != 0);
        } else {
            a.reads = true; // fuente, o instruccion que solo compara
        }
        break;
    }
    return a;
}

/**
 * @brief Marca que registros llevan los argumentos al entrar a una funcion.
 *
 * Lo dice la convencion de llamada, que es parte del idioma de la ISA tanto como
 * los mnemonicos.  Sin esto, un `[rdx+0x8]` es una carga cualquiera; con esto es
 * "un campo del SEGUNDO argumento", que es lo que permite decir de QUE operando
 * salio un indice.
 */
inline void seed_args(TableState &st) {
#if defined(_WIN32)
    // Windows x64: RCX, RDX, R8, R9.
    st.arg[1] = 0;  // rcx
    st.arg[2] = 1;  // rdx
    st.arg[8] = 2;  // r8
    st.arg[9] = 3;  // r9
#else
    // System V: RDI, RSI, RDX, RCX.
    st.arg[7] = 0;  // rdi
    st.arg[6] = 1;  // rsi
    st.arg[2] = 2;  // rdx
    st.arg[1] = 3;  // rcx
#endif
}

/// Cuantos argumentos viajan en registro.  Los que se derraman a la pila no se
/// siguen: haria falta rastrear el marco, y ninguna forma los usa.
constexpr int kArgRegs = 4;

/// La ranura de registro donde viaja el argumento @p n, o -1.
inline int arg_slot(int n) {
#if defined(_WIN32)
    static const int kSlots[kArgRegs] = {1, 2, 8, 9}; // rcx rdx r8 r9
#else
    static const int kSlots[kArgRegs] = {7, 6, 2, 1}; // rdi rsi rdx rcx
#endif
    return (n >= 0 && n < kArgRegs) ? kSlots[n] : -1;
}

/**
 * @brief Lo que el llamante dejo en los argumentos, para seguirlo al otro lado.
 *
 * Solo lleva DIRECCIONES.  Un valor cualquiera no dice nada util al cruzar la
 * llamada, pero un puntero a `regs[campo]` si: es lo que convierte el acceso
 * que hace el ayudante en un acceso atribuible al campo del operando.
 */
struct CallSeed {
    AddrOrigin arg[kArgRegs];
    bool any = false; ///< hay algo que sembrar; si no, ni se mira
};

/// Apunta que direcciones lleva cada argumento en este punto.
inline CallSeed capture_call_seed(const TableState &st) {
    CallSeed s;
    for (int n = 0; n < kArgRegs; ++n) {
        const int slot = arg_slot(n);
        if (slot < 0) continue;
        s.arg[n] = st.addr[slot];
        if (s.arg[n].valid) s.any = true;
    }
    return s;
}

/// Siembra en el callee lo que el llamante puso en los argumentos.
inline void apply_call_seed(TableState &st, const CallSeed &s) {
    for (int n = 0; n < kArgRegs; ++n) {
        const int slot = arg_slot(n);
        if (slot >= 0 && s.arg[n].valid) st.addr[slot] = s.arg[n];
    }
}

/// Termina aqui la funcion?
inline bool is_return(const cs_insn &in) {
    const char *m = in.mnemonic;
    return std::strcmp(m, "ret") == 0 || std::strcmp(m, "retq") == 0;
}

/// Es una llamada?
inline bool is_call(const cs_insn &in) {
    const char *m = in.mnemonic;
    return std::strcmp(m, "call") == 0 || std::strcmp(m, "callq") == 0;
}

/// Es un salto (condicional o no)?
inline bool is_jump(const cs_insn &in) { return in.mnemonic[0] == 'j'; }

/// Es un salto INCONDICIONAL?  Uno asi al final es una llamada de cola.
inline bool is_tail_jump(const cs_insn &in) {
    return std::strcmp(in.mnemonic, "jmp") == 0;
}

/// @return El destino si esta en la instruccion; 0 si es indirecto.
inline uint64_t branch_target(const cs_insn &in) {
    if (in.op_str[0] != '0' || in.op_str[1] != 'x') return 0;
    return strtoull(in.op_str + 2, nullptr, 16);
}

} // namespace isa_x86

/* El idioma que se usa.  Es un alias de compilacion, no un puntero: la ISA es la
 * de la maquina donde se compilo -- lo que se recorre es el codigo maquina de
 * este mismo binario --, asi que no hay nada que elegir en ejecucion ni ningun
 * despacho que pagar. */
namespace isa = isa_x86;

/// Compatibilidad con quien ya abria Capstone con estos nombres.
constexpr cs_arch kWalkArch = isa::kArch;
constexpr cs_mode kWalkMode = isa::kMode;

/// El estado de registros que lleva el idioma en uso.
using TableState = isa::TableState;

/// De donde salio lo que lleva un registro, segun el idioma en uso.  Es un rango
/// de BITS a proposito: que trozo corresponde a que campo lo decide quien conoce
/// nuestra codificacion, no la ISA.
using Origin = isa::Origin;

/// Una direccion calculada y aun sin desreferenciar.  Ver `isa::AddrOrigin`.
using AddrOrigin = isa::AddrOrigin;

/// Lo que el llamante dejo en los argumentos.  Ver `isa::CallSeed`.
using CallSeed = isa::CallSeed;

/// Que se pudo ver del recorrido.
struct WalkResult {
    uint32_t instrs = 0;          ///< instrucciones recorridas
    uint32_t saltos_atras = 0;    ///< bucles dentro de la funcion
    uint32_t saltos_adelante = 0; ///< ramas dentro de la funcion
    /// Llamadas vistas, se hayan seguido o no.  Quien estime COSTE lo necesita
    /// aparte: aunque la llamada se siga, el coste deja de ser exacto porque no
    /// se sabe cuantas veces se ejecuta lo de dentro.
    uint32_t llamadas = 0;
    uint32_t sin_seguir = 0; ///< llamadas/saltos INDIRECTOS: hay codigo que no
                             ///< se ha mirado
    bool truncado = false;   ///< se llego al tope sin ver el final
    /// Despachos por tabla de punteros que SI se pudieron seguir.  Se cuenta
    /// aparte de `llamadas` porque es lo que separa una cota inferior de un
    /// dato exacto en toda la familia ALU.
    uint32_t tables_resolved = 0;
    /* DONDE se quedo el recorrido, cuando se queda corto.
     *
     * Un analisis que renuncia sin decir por que es un fallo escondido: parece
     * que funciona.  Y aqui hace falta para algo concreto -- en una VM PROPIA
     * no puede haber instrucciones con efectos desconocidos, asi que cada
     * renuncia es trabajo pendiente, y sin la direccion no se sabe cual. */
    std::vector<std::string> unresolved;

    /// true si lo recorrido es todo lo que se ejecuta.  Con `sin_seguir` o
    /// `truncado` el resultado es una COTA, no la verdad completa.
    bool completo() const { return sin_seguir == 0 && !truncado; }
};

/// Se llama con cada instruccion recorrida.
/// Se llama con cada instruccion y con lo que se sabe de los registros en ese
/// punto.  El estado va incluido porque sin el no se puede responder "este
/// indice, de que campo salio?", y el recorredor es el unico que lo lleva.
using WalkVisitor = std::function<void(const cs_insn &, const TableState &)>;

/**
 * @brief Recorre desde @p dir hasta el final de la funcion, siguiendo llamadas.
 *
 * El final es un `ret`, o un `jmp` fuera del rango recorrido (tail call: el
 * optimizador saca cuerpo comun a funciones aparte, y sin seguirlo se recorre
 * un stub de tres instrucciones en vez del trabajo de verdad).
 *
 * @param cs          Handle de Capstone, con el detalle ACTIVADO si el
 *                    visitante mira operandos (`cs_option(cs, CS_OPT_DETAIL,
 *                    CS_OPT_ON)`).
 * @param dir         Direccion de la funcion.
 * @param profundidad Cuantas llamadas encadenadas seguir.  Sin tope, un
 *                    manejador que llama al runtime arrastraria medio binario.
 * @param vistas      Direcciones ya recorridas: corta la recursion y evita
 *                    contar dos veces lo compartido.
 * @param ver         Visitante.
 * @param res         Se acumula sobre el: se puede recorrer varias raices.
 * @param seed        Que direcciones dejo el llamante en los argumentos.  Vacia
 *                    en la raiz; llena al bajar por una llamada, que es lo que
 *                    permite atribuir al campo correcto un acceso que el
 *                    ayudante hace por un puntero que le pasaron.
 */
inline void walk_handler(csh cs, uint64_t dir, int profundidad,
                         std::set<uint64_t> &vistas, const WalkVisitor &ver,
                         WalkResult &res, const CallSeed &seed = CallSeed{}) {
    if (profundidad < 0 || dir == 0 || !vistas.insert(dir).second) return;

    const uint8_t *code = reinterpret_cast<const uint8_t *>(dir);
    size_t restante = kWalkBytesMax;
    uint64_t addr = dir;
    cs_insn *insn = cs_malloc(cs);
    if (insn == nullptr) return;

    const uint64_t lo = dir;
    uint64_t hi = dir;
    /* Llamadas a seguir al terminar, cada una con lo que el llamante dejo en
     * los argumentos.
     *
     * Limitacion conocida: `vistas` corta por direccion, asi que un ayudante
     * alcanzado DOS veces con semillas distintas solo se recorre con la primera.
     * Se pierde atribucion, nunca se inventa -- el segundo camino queda como
     * "no se sabe", que es el lado seguro. */
    std::vector<std::pair<uint64_t, CallSeed>> pendientes;
    std::vector<std::string> previas; // ultimas instrucciones, para el contexto
    /* Bases de tabla y cotas de indice vistas hasta aqui.  Es estado LINEAL:
     * no sabe de ramas, y por eso una base equivocada se descarta al comprobar
     * que sus entradas no apuntan a codigo. */
    TableState table_state;
    /* Los argumentos, sembrados con la convencion de la ISA.  Es lo que permite
     * saber que un `[rdx+0x8]` es "un campo del SEGUNDO argumento" y no una
     * carga cualquiera. */
    isa::seed_args(table_state);
    /* Y encima, lo que el llamante puso ahi.  Sin esto un ayudante ve "arg1 es
     * un puntero" y nada mas; con esto ve "arg1 es &regs[el primer campo]". */
    isa::apply_call_seed(table_state, seed);

    while (cs_disasm_iter(cs, &code, &restante, &addr, insn)) {
        res.instrs++;
        hi = insn->address;
        ver(*insn, table_state);
        /* Lo que esta instruccion dice de los registros, antes de mirar si es
         * una llamada: la `and` que acota el indice es una instruccion aparte,
         * y sin apuntarla no habria con que resolver la tabla. */
        isa::track_table_state(cs, *insn, table_state);
        {
            char pb[160];
            std::snprintf(pb, sizeof(pb), "0x%llX: %s %s",
                          (unsigned long long)insn->address, insn->mnemonic,
                          insn->op_str);
            previas.push_back(pb);
            if (previas.size() > 5) previas.erase(previas.begin());
        }

        // Destino inmediato del salto o la llamada, si lo hay.  Un salto por
        // registro no lo tiene, y eso ya es motivo para no prometer exactitud.
        const uint64_t destino = isa::branch_target(*insn);

        if (isa::is_return(*insn)) break;
        if (isa::is_call(*insn)) {
            res.llamadas++;
            /* Lo que va en los argumentos AHORA, antes de que la llamada
             * machaque el estado.  Es la unica ventana: pasado el `call` ya no
             * se sabe que llevaba ninguno. */
            const CallSeed sub = isa::capture_call_seed(table_state);
            std::vector<uint64_t> destinos;
            if (destino) {
                destinos.push_back(destino);
            } else if (const uint64_t ext = isa::indirect_call_target(*insn)) {
                /* Llamada por la tabla de importaciones: la ranura tiene
                 * direccion fija, asi que el destino se LEE.  Se sigue como
                 * cualquier otra. */
                destinos.push_back(ext);
                res.tables_resolved++;
            } else if (const uint32_t n = isa::resolve_dispatch_table(
                           *insn, table_state, destinos)) {
                // Despacho por tabla: los destinos SI se conocen, asi que esto
                // deja de ser un agujero.  Es el caso de la familia ALU.
                res.tables_resolved++;
                (void)n;
            } else {
                res.sin_seguir++; // llamada indirecta: no se ve el destino
                if (res.unresolved.size() < 8) {
                    /* Se guardan tambien las instrucciones de ANTES.  El
                     * destino de un `call rax` no esta en el `call`: esta en lo
                     * que cargo `rax`, y sin verlo la renuncia no es
                     * accionable -- dice que no se sabe, no que cerrar. */
                    std::string ctx;
                    for (const std::string &p : previas) ctx += "\n      " + p;
                    char b[160];
                    std::snprintf(b, sizeof(b), "0x%llX: %s %s",
                                  (unsigned long long)insn->address,
                                  insn->mnemonic, insn->op_str);
                    res.unresolved.push_back(std::string(b) + ctx);
                }
}
            for (uint64_t d : destinos) pendientes.emplace_back(d, sub);
            /* Tras la llamada no se sabe que queda en los registros -- la
             * convencion permite machacar la mitad --, asi que se olvida todo.
             * Perder una base solo cuesta una resolucion; conservar una que ya
             * no vale es leer una tabla que no es. */
            table_state = TableState{};
            continue;
        }
        if (isa::is_jump(*insn)) {
            /* Un salto de cola no monta marco: el destino recibe los MISMOS
             * argumentos que tiene esta funcion ahora mismo.  Por eso la semilla
             * se toma igual que en un `call`. */
            const CallSeed sub = isa::capture_call_seed(table_state);
            std::vector<uint64_t> destinos;
            if (!destino) {
                res.llamadas++; // salto indirecto: se trata como no seguible
                if (const uint64_t ext = isa::indirect_call_target(*insn)) {
                    /* `jmp qword ptr [rip+disp]` es el thunk de importacion:
                     * un salto de cola a otro modulo, con la direccion en una
                     * ranura fija.  Mismo caso que el `call` equivalente, y era
                     * la causa de 34 de los 56 huecos. */
                    destinos.push_back(ext);
                    res.tables_resolved++;
                } else if (const uint32_t n = resolve_dispatch_table(
                        *insn, table_state, destinos)) {
                    res.tables_resolved++;
                    (void)n;
                } else {
                res.sin_seguir++;
                if (res.unresolved.size() < 8) {
                    /* El sitio TAMBIEN para los saltos indirectos.  Sin esto
                     * salian sin sitio y mi informe los llamaba "truncado por
                     * tamano", que es otra cosa: 27 opcodes acusados de una
                     * causa que no era la suya. */
                    std::string ctx;
                    for (const std::string &p : previas) ctx += "\n      " + p;
                    char b[160];
                    std::snprintf(b, sizeof(b), "0x%llX: %s %s",
                                  (unsigned long long)insn->address,
                                  insn->mnemonic, insn->op_str);
                    res.unresolved.push_back(std::string(b) + ctx);
                }
                }
            } else if (destino <= insn->address && destino >= lo) {
                res.saltos_atras++;
            } else if (destino > hi && destino < lo + kWalkBytesMax) {
                res.saltos_adelante++;
            } else if (isa::is_tail_jump(*insn)) {
                destinos.push_back(destino); // tail call
                for (uint64_t d : destinos) pendientes.emplace_back(d, sub);
                break;
            }
            for (uint64_t d : destinos) pendientes.emplace_back(d, sub);
        }
        if (res.instrs > kWalkInstrMax) {
            res.truncado = true;
            break;
        }
    }
    cs_free(insn, 1);

    for (const auto &p : pendientes)
        walk_handler(cs, p.first, profundidad - 1, vistas, ver, res, p.second);
}

} // namespace tests

#endif // VESTA_TESTS_HANDLER_WALK_H
