/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/unwind/dwarf_cfi.cpp
 * @brief Implementacion del codificador de CFI (ver la cabecera).
 */

#include "codegen/unwind/dwarf_cfi.h"

#include <cstddef>

namespace codegen {
namespace unwind {

namespace {

/* -------------------------------------------------------------------------
 *  Opcodes de CFI.
 *
 *  QUE ES ESTO, en una frase: un programa.  La CFI no es una tabla de datos,
 *  es una maquina de estados que se ejecuta de principio a fin y va diciendo,
 *  para cada tramo de codigo, donde esta el CFA -- la "direccion canonica del
 *  marco", que por definicion es el valor que tenia `rsp` justo ANTES de la
 *  llamada -- y en que sitio quedo guardado cada registro respecto a el.
 *
 *  Todo se expresa relativo al CFA y no a `rsp` a proposito: `rsp` se mueve
 *  constantemente dentro de la funcion, y el CFA no se mueve nunca.  Por eso
 *  una sola regla vale para todo el cuerpo.
 *
 *  Se nombran en vez de escribir el numero suelto porque leer `0x0C` y `0x0E`
 *  seguidos no dice nada, y son dos cosas bien distintas: "el CFA pasa a
 *  calcularse desde OTRO registro" frente a "el CFA sigue donde estaba pero a
 *  otra distancia".
 * ------------------------------------------------------------------------- */

/// No hace nada.  Sirve de relleno para cuadrar el tamano de un registro.
constexpr uint8_t DW_CFA_nop = 0x00;
/// "Las reglas que siguen empiezan N bytes mas adelante", con N en 1 byte.
constexpr uint8_t DW_CFA_advance_loc1 = 0x02;
/// Igual, con N en 2 bytes (prologos de mas de 255 bytes).
constexpr uint8_t DW_CFA_advance_loc2 = 0x03;
/// Igual, con N en 4 bytes.
constexpr uint8_t DW_CFA_advance_loc4 = 0x04;
/// "El CFA es <registro> + <desplazamiento>".  Fija los dos de una vez.
constexpr uint8_t DW_CFA_def_cfa = 0x0C;
/// "El CFA pasa a contarse desde <registro>", conservando el desplazamiento.
constexpr uint8_t DW_CFA_def_cfa_register = 0x0D;
/// "El CFA cambia de desplazamiento", conservando el registro.
constexpr uint8_t DW_CFA_def_cfa_offset = 0x0E;

/* Los dos siguientes llevan su operando DENTRO del propio byte: el opcode
 * ocupa los bits altos y el resto es el numero.  Es lo que hace que la CFI
 * ocupe tan poco, y tambien lo que obliga a comprobar el rango antes de
 * componer el byte -- un valor que se sale se comeria el opcode. */

/// 0x40 | delta: avanzar, para delta < 64.  La forma mas corta que hay.
constexpr uint8_t DW_CFA_advance_loc_hi = 0x40;
/// 0x80 | reg: "<registro> quedo guardado en CFA + N * factor", N en ULEB.
constexpr uint8_t DW_CFA_offset_hi = 0x80;

/* La codificacion de puntero de las FDE: relativa a la posicion del propio
 * campo, con signo y cuatro bytes.
 *
 * Se elige pcrel y no una direccion absoluta a proposito.  Una absoluta
 * obligaria a que el cargador reubicara la seccion en cada arranque de un
 * binario reubicable, con lo que `.eh_frame` dejaria de poder ser de solo
 * lectura y compartida entre procesos.  Con pcrel el valor lo calcula quien
 * emite y no hace falta tocar nada en tiempo de carga.  Es lo que producen
 * todas las cadenas de herramientas, y por este motivo. */
constexpr uint8_t DW_EH_PE_pcrel_sdata4 = 0x1B;

/// El registro DWARF que representa la direccion de retorno en x86-64.
constexpr uint32_t DWARF_RA_X86_64 = 16;
/// Numero DWARF de `rsp` y de `rbp` (que NO son 4 y 5, ver la traduccion).
constexpr uint32_t DWARF_RSP = 7;

/// Anade un byte tal cual.
void put8(std::vector<uint8_t> &v, uint8_t x) {
    v.push_back(x);
}

/// Anade cuatro bytes en little endian.
///
/// Byte a byte y no con un `memcpy` del entero porque el formato es
/// little endian SIEMPRE, tambien si algun dia se genera desde una maquina que
/// no lo sea: quien produce un binario para otra arquitectura no puede heredar
/// el orden de bytes de la suya.
void put32(std::vector<uint8_t> &v, uint32_t x) {
    for (int i = 0; i < 4; ++i)
        v.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xFF));
}

/**
 * @brief Entero SIN signo de longitud variable (ULEB128).
 *
 * Siete bits utiles por byte; el octavo dice si viene otro.  DWARF lo usa en
 * casi todos los operandos porque la inmensa mayoria son numeros pequenos --
 * un registro, un desplazamiento de pocas palabras -- y asi ocupan un byte.
 *
 * Es un `do/while` y no un `while`: el cero tambien tiene que escribirse, y
 * con la condicion delante no se emitiria ningun byte.
 *
 * @param v [in,out] destino, se anade al final.
 * @param x valor a escribir.
 */
void uleb(std::vector<uint8_t> &v, uint64_t x) {
    do {
        uint8_t b = static_cast<uint8_t>(x & 0x7F);
        x >>= 7;
        if (x) b |= 0x80;
        v.push_back(b);
    } while (x);
}

/**
 * @brief Entero CON signo de longitud variable (SLEB128).
 *
 * No vale reutilizar el de arriba, y la diferencia es sutil: aqui el final no
 * lo decide que se hayan agotado los bits, sino que lo que queda coincida con
 * la extension de signo del ultimo byte escrito.  Por eso se mira el bit 0x40
 * -- el de signo del grupo de siete -- y se compara el resto con 0 o con -1
 * segun el caso.
 *
 * Se nota justo en el valor que este fichero necesita: `-8` sale como un solo
 * byte, 0x78.  Escrito con las reglas del sin signo saldrian dos, y ningun
 * lector lo interpretaria como -8.
 *
 * @param v [in,out] destino, se anade al final.
 * @param x valor a escribir, con signo.
 */
void sleb(std::vector<uint8_t> &v, int64_t x) {
    bool more = true;
    while (more) {
        uint8_t b = static_cast<uint8_t>(x & 0x7F);
        x >>= 7; // aritmetico: propaga el signo
        const bool sign_bit = (b & 0x40) != 0;
        if ((x == 0 && !sign_bit) || (x == -1 && sign_bit))
            more = false;
        else
            b |= 0x80;
        v.push_back(b);
    }
}

/**
 * @brief Emite "las reglas que siguen empiezan @p delta bytes mas adelante".
 *
 * Hay cuatro formas del mismo avance y se elige la mas corta que admita el
 * valor, porque esta seccion se paga en tamano en todos los binarios: hasta 63
 * cabe en el propio opcode, y a partir de ahi hacen falta 1, 2 o 4 bytes de
 * operando.
 *
 * @param v     [in,out] destino.
 * @param delta cuantos bytes de codigo se avanza.  Cero no emite nada -- el
 *              avance nulo es un byte gastado en no decir nada.
 */
void advance_loc(std::vector<uint8_t> &v, uint32_t delta) {
    if (delta == 0) return;
    if (delta < 64) {
        put8(v, static_cast<uint8_t>(DW_CFA_advance_loc_hi | delta));
    } else if (delta <= 0xFF) {
        put8(v, DW_CFA_advance_loc1);
        put8(v, static_cast<uint8_t>(delta));
    } else if (delta <= 0xFFFF) {
        put8(v, DW_CFA_advance_loc2);
        put8(v, static_cast<uint8_t>(delta & 0xFF));
        put8(v, static_cast<uint8_t>(delta >> 8));
    } else {
        put8(v, DW_CFA_advance_loc4);
        put32(v, delta);
    }
}

/**
 * @brief Cierra un registro: lo rellena hasta alinear y le escribe su longitud.
 *
 * Los dos pasos van juntos porque dependen uno del otro -- la longitud incluye
 * el relleno --, y separarlos es la manera de que alguien anada un byte
 * despues de calcularla.
 *
 * LA LONGITUD NO SE CUENTA A SI MISMA: significa "cuantos bytes vienen detras
 * de este campo".  Es lo que permite recorrer `.eh_frame` entera saltando de
 * registro en registro sin entender el contenido de ninguno, que es justo lo
 * que hace un desenrollador buscando la funcion que le interesa.
 *
 * El relleno es @c DW_CFA_nop y no ceros arbitrarios: el contenido de un
 * registro es un programa que se ejecuta hasta el final, asi que el relleno
 * tambien se ejecuta y tiene que ser inofensivo.
 *
 * @param v [in,out] el registro completo, con sus cuatro primeros bytes
 *          reservados para la longitud.
 * @param a alineamiento al que se rellena (8 para la CIE, 4 para las FDE).
 */
void close_record(std::vector<uint8_t> &v, size_t a) {
    while (v.size() % a)
        put8(v, DW_CFA_nop);
    const uint32_t len = static_cast<uint32_t>(v.size() - 4);
    for (int i = 0; i < 4; ++i)
        v[static_cast<size_t>(i)] = static_cast<uint8_t>((len >> (i * 8)) & 0xFF);
}

} // namespace

uint32_t dwarf_reg_x86_64(uint32_t reg) noexcept {
    /* Solo se cruzan los ocho primeros; de r8 en adelante coinciden.
     *
     * Se escribe como CORRESPONDENCIA y no como dos filas de nombres: leerlo
     * por posiciones -- "el 4 es rsp aqui y rsi alli" -- invita a copiar la
     * fila de abajo como si fuera la traduccion, y no lo es.  Lo que hace
     * falta es, para cada registro, su numero en el otro lado:
     *
     *     rax 0->0   rcx 1->2   rdx 2->1   rbx 3->3
     *     rsp 4->7   rbp 5->6   rsi 6->4   rdi 7->5      */
    static constexpr uint32_t table[8] = {0, 2, 1, 3, 7, 6, 4, 5};
    if (reg < 8) return table[reg];
    return reg; // r8-r15 y cualquier otra cosa, tal cual
}

void build_eh_frame_cie_x86_64(std::vector<uint8_t> &out) {
    out.clear();
    put32(out, 0);  // longitud: se rellena en close_record()
    put32(out, 0);  // CIE_id: cero identifica a una CIE en `.eh_frame`
    put8(out, 1);   // version

    /* "zR": la 'z' anuncia que hay un bloque de datos de aumento con su
     * longitud delante -- de modo que quien no entienda el resto pueda
     * SALTARLO en vez de atragantarse --, y la 'R' dice que ese bloque trae la
     * codificacion de los punteros de las FDE. */
    put8(out, 'z');
    put8(out, 'R');
    put8(out, 0);

    uleb(out, 1);   // factor de alineamiento de codigo: 1 byte
    sleb(out, -8);  // factor de alineamiento de datos: la pila crece hacia abajo
    uleb(out, DWARF_RA_X86_64); // que registro es la direccion de retorno

    uleb(out, 1); // longitud de los datos de aumento
    put8(out, DW_EH_PE_pcrel_sdata4);

    /* Reglas de la ENTRADA a la funcion, antes de ejecutar nada: el `call` ya
     * apilo la direccion de retorno, asi que `rsp` apunta a ella y el CFA --
     * que por definicion es `rsp` ANTES de la llamada -- esta 8 bytes mas
     * arriba.  La direccion de retorno, por tanto, en CFA-8. */
    put8(out, DW_CFA_def_cfa);
    uleb(out, DWARF_RSP);
    uleb(out, 8);
    put8(out, static_cast<uint8_t>(DW_CFA_offset_hi | DWARF_RA_X86_64));
    uleb(out, 1); // 1 * (-8) = -8  ->  CFA-8

    close_record(out, 8);
}

bool build_eh_frame_fde_x86_64(const FrameUnwind &frame, uint32_t code_size,
                               uint32_t cie_offset, uint32_t fde_offset,
                               std::vector<uint8_t> &out,
                               uint32_t *pc_begin_off) noexcept {
    out.clear();
    if (pc_begin_off) *pc_begin_off = 0;

    /* Igual que en PE: si el cuerpo se apana la pila por su cuenta, no hay
     * prologo que describir y una descripcion inventada es peor que ninguna. */
    if (frame.owns_stack) return false;

    put32(out, 0); // longitud: se rellena en close_record()

    /* Enlace a la CIE: la DISTANCIA hacia atras desde este mismo campo hasta
     * donde empieza la CIE.  Es una distancia y no un offset absoluto para que
     * la seccion se pueda concatenar con la de otro objeto sin reescribirla. */
    const uint32_t aqui = fde_offset + 4;
    put32(out, aqui - cie_offset);

    if (pc_begin_off) *pc_begin_off = static_cast<uint32_t>(out.size());
    put32(out, 0);         // direccion de la funcion: hueco para la relocation
    put32(out, code_size); // cuanto abarca

    uleb(out, 0); // sin datos de aumento en la FDE

    /* Todas las reglas se situan al FINAL del prologo.  Ver la nota de la
     * cabecera: dentro del prologo mandan las de la CIE, que son las de la
     * entrada, y eso es exacto en la primera instruccion y aproximado despues.
     * Es la misma fidelidad que da la version de PE. */
    if (!frame.ops.empty()) advance_loc(out, frame.prologue_bytes);

    /* Se recorre en orden de EJECUCION, al reves que el codificador de PE.
     *
     * No es una diferencia de gusto: alli la descripcion se lee de atras hacia
     * delante para deshacer el prologo, y aqui hace falta saber cuanto habia
     * crecido la pila EN EL MOMENTO en que se guardo cada registro -- porque el
     * sitio que le toco depende de lo que se apilo antes que el.  Ese dato solo
     * sale recorriendo hacia delante y llevando la cuenta.
     *
     * Lo que se calcula es el estado FINAL del prologo, y se emite entero de
     * una vez.  Las reglas de guardado no dependen del orden en que se
     * escriban, asi que no hace falta ir intercalandolas. */

    /// A que distancia esta el CFA del tope de pila actual.
    ///
    /// Empieza en 8 y no en 0 porque el `call` que trajo aqui ya apilo la
    /// direccion de retorno: es lo que dice la CIE, y esto continua esa cuenta.
    uint64_t cfa_off = 8;

    /// Si el prologo llego a establecer un puntero de marco, y cual.
    bool has_fp = false;
    uint32_t fp_reg = 0;
    /// Cuanto valia @c cfa_off en el instante de establecerlo.  Ese es el
    /// numero que queda fijo para siempre, y por eso se guarda aparte.
    uint64_t fp_cfa_off = 0;

    /// Un registro salvado y a que profundidad quedo, ya en unidades del
    /// factor de alineamiento de datos (-8), que es como lo pide el formato.
    struct Saved {
        uint32_t reg;    ///< numero DWARF, ya traducido
        uint64_t factor; ///< N tal que el registro esta en CFA - 8*N
    };
    /* Dieciseis y no un vector: el banco general de x86-64 tiene ese tamano y
     * un prologo no puede guardar mas registros de los que hay.  Evita reservar
     * memoria por cada funcion que se compila, que aqui son muchas. */
    Saved saved[16];
    size_t n_saved = 0;

    for (const FrameOp &op : frame.ops) {
        switch (op.kind) {
        case FrameOp::Kind::SaveReg:
            // Solo el banco general: uno ancho no se salva con un push.
            if (op.reg > 15) break;
            cfa_off += 8;
            if (n_saved < 16) {
                saved[n_saved].reg = dwarf_reg_x86_64(op.reg);
                // El registro queda en CFA - cfa_off; el factor es -8.
                saved[n_saved].factor = cfa_off / 8;
                ++n_saved;
            }
            break;
        case FrameOp::Kind::SetFramePointer:
            /* Al copiar `rsp` al puntero de marco, ese registro pasa a valer
             * lo que valia `rsp` aqui, o sea CFA - cfa_off.  De ahi que el CFA
             * quede en `fp + cfa_off`, y ya no se mueva por mucho que la pila
             * siga bajando: es justo para lo que sirve un puntero de marco. */
            has_fp = true;
            fp_reg = op.reg;
            fp_cfa_off = cfa_off;
            break;
        case FrameOp::Kind::AllocStack:
            // Con puntero de marco el CFA ya no depende de `rsp`.
            if (!has_fp) cfa_off += op.bytes;
            break;
        }
    }

    /* Donde queda el CFA al acabar el prologo.
     *
     * Con puntero de marco cambia el REGISTRO desde el que se cuenta, y el
     * desplazamiento solo si dejo de ser el 8 que traia la CIE.  Se emiten como
     * dos ordenes y no como un `def_cfa` unico porque asi la segunda se ahorra
     * en el caso corriente, que es una funcion sin nada apilado antes del
     * puntero de marco.
     *
     * Sin puntero de marco el registro sigue siendo `rsp`, asi que basta con el
     * desplazamiento -- y si tampoco cambio, no hay nada que decir: las reglas
     * de la CIE ya describen la funcion entera.  Ese es el caso de la hoja. */
    if (has_fp) {
        put8(out, DW_CFA_def_cfa_register);
        uleb(out, dwarf_reg_x86_64(fp_reg));
        if (fp_cfa_off != 8) {
            put8(out, DW_CFA_def_cfa_offset);
            uleb(out, fp_cfa_off);
        }
    } else if (cfa_off != 8) {
        put8(out, DW_CFA_def_cfa_offset);
        uleb(out, cfa_off);
    }

    /* Y donde quedo cada registro salvado.  Van despues del CFA a proposito:
     * describen posiciones RELATIVAS a el, asi que el lector tiene que saber
     * primero donde esta.
     *
     * El limite de 64 no es formalismo: el numero se mete en los bits bajos del
     * propio opcode, asi que uno mas alto se comeria el opcode y produciria una
     * orden distinta.  No puede pasar con el banco general de x86-64 -- llega a
     * 15 --, y se comprueba igualmente porque el dia que entre otro banco el
     * fallo seria silencioso. */
    for (size_t i = 0; i < n_saved; ++i) {
        const Saved &g = saved[i];
        if (g.reg < 64) {
            put8(out, static_cast<uint8_t>(DW_CFA_offset_hi | g.reg));
            uleb(out, g.factor);
        }
    }

    /* Se rellena a OCHO, el tamano de un puntero, no a cuatro.
     *
     * No es cosmetico y no se ve probando una FDE sola: al enlazar, la seccion
     * es la concatenacion de las aportaciones de cada objeto, y cada una empieza
     * en un limite de ocho.  Si una acaba en un multiplo de cuatro que no lo es
     * de ocho, el enlazador mete cuatro ceros para cuadrar -- y cuatro ceros
     * SON un registro de longitud cero, o sea un terminador.  Un lector que
     * recorra la seccion se para ahi y da por vacio todo lo que aporten los
     * objetos siguientes.
     *
     * Rellenando a ocho, ninguna aportacion deja hueco y el problema no llega a
     * existir.  Es lo que hacen gcc y clang, y ahora se sabe por que. */
    close_record(out, 8);
    return true;
}

} // namespace unwind
} // namespace codegen
