/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file vx/asm/asm_lift_micro.cpp
 * @brief Lift de instrucciones asm opacas SIN operandos de registro a
 *        @c IrOp::ASM_MICRO.  Ver vx/asm/asm_lift_micro.h.
 */

#include "util/env_flags.h"
#include "vx/asm/asm_lift_reason.h"
#include "vx/asm/asm_lift_micro.h"

#include "ir/ssa_ir.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include "vx/asm/asm_cfg.h"
#include "vx/asm/asm_effects.h"
#include "vx/asm/asm_phys_reg.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <unordered_map>
#include <set>
#include <string>
#include <vector>

namespace vx {

namespace {

/// Instrucciones que la base de datos no supo resolver, con el motivo.  Se
/// guardan por (mnemonico, motivo) para no repetir la misma cien veces.
std::set<std::pair<std::string, std::string>> &huecos_db() {
    static std::set<std::pair<std::string, std::string>> s;
    return s;
}
std::mutex &huecos_db_mutex() {
    static std::mutex m;
    return m;
}

/// Recorta espacios de los extremos.
std::string trim(const std::string &s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a]))
        ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1]))
        --b;
    return s.substr(a, b - a);
}

/// Divide el cuerpo en instrucciones (una por linea), descartando comentarios
/// (@c // y @c ;) y etiquetas (@c "name:").
std::vector<std::string> instructions(const std::string &body) {
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos <= body.size()) {
        size_t nl = body.find('\n', pos);
        std::string ln = body.substr(
            pos, nl == std::string::npos ? std::string::npos : nl - pos);
        // Quitar comentario // o ;
        size_t c = ln.find("//");
        if (c != std::string::npos) ln.resize(c);
        c = ln.find(';');
        if (c != std::string::npos) ln.resize(c);
        ln = trim(ln);
        if (!ln.empty() && ln.back() != ':') // no etiqueta
            out.push_back(ln);
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return out;
}

/// Empaqueta los efectos de la DB en el byte @c eff de @ref ir::AsmMicro:
/// bit0 memoria, bit1 lee flags, bit2 escribe flags, bit3 barrera.
uint8_t pack_eff(const instr_db::AsmInsnSem &sem) {
    uint8_t e = 0;
    if (sem.reads_mem || sem.writes_mem) e |= 0x1;
    if (sem.reads_flags) e |= 0x2;
    if (sem.writes_flags) e |= 0x4;
    if (sem.barrier) e |= 0x8;
    return e;
}

/**
 * @brief ¿Se elevan tambien los bloques cuyos operandos son variables del
 *        programa?
 *
 * Un operando ligado con @c register() no es un registro opaco: es una
 * variable, y lo que tiene que viajar es su VALOR.  Sin esto el elevado no
 * llegaba a ningun bloque real: TODOS los del corpus tienen ligaduras, y el
 * corpus se quedaba con cero instrucciones elevadas.
 */
bool elevar_ligados() {
    /* Ya es lo normal.  Se apaga a mano solo para comparar una version con la
     * otra cuando algo no cuadra; mientras se construia iba al reves. */
    /* El mando dice NO elevar; esto responde a "elevar", asi que va negado. */
    static const bool v = !util::flag_on(util::FlagId::AsmNoLiftSsa);
    return v;
}

/// Minusculas de @p s.
std::string lower(const std::string &s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s)
        o += (char)std::tolower((unsigned char)c);
    return o;
}

/// ¿Contiene @p v (canonico, minusculas) el nombre @p name?
bool has_reg(const std::vector<std::string> &v, const std::string &name) {
    for (const std::string &r : v)
        if (lower(r) == name) return true;
    return false;
}

/// Trocea @p insn en (mnemonico, operandos por coma).  Los operandos van con
/// espacios recortados.  No maneja @c [...] (= solo registros GP).
/**
 * @brief Deja constancia de que la base de datos no supo resolver @p insn.
 *
 * Que una instruccion no este en la base de datos no impide compilar -- se
 * trata como una caja opaca -- pero casi siempre significa que falta en la
 * base, y eso hay que poder verlo.  Con @c VESTA_ASM_DB_GAPS=1 se avisa de
 * cada una la primera vez.
 *
 * @param insn Instruccion tal cual aparece en el bloque asm.
 * @param motivo Por que no se pudo resolver.
 */
void anotar_hueco_db(const std::string &insn, const char *motivo) {
    bool nuevo = false;
    {
        std::lock_guard<std::mutex> g(huecos_db_mutex());
        nuevo = huecos_db().emplace(insn, motivo).second;
    }
    if (!nuevo) return;
    if (!util::flag_on(util::FlagId::AsmDbGaps)) return;
    std::fprintf(stderr, "[asm-db] '%s': %s\n", insn.c_str(), motivo);
}

/**
 * @brief ¿Es @p tok un PREFIJO y no una instruccion?
 *
 * `rep stosb` se partia como mnemonico `rep` con operando `stosb`, y por eso la
 * base de datos "no lo conocia": se le preguntaba por un prefijo y se le daba
 * una instruccion como operando.  La base SI tiene `stosb`; lo que estaba mal
 * era la pregunta.
 */
bool es_prefijo(const std::string &tok) {
    const std::string t = lower(tok);
    return t == "rep" || t == "repe" || t == "repz" || t == "repne" ||
           t == "repnz" || t == "lock";
}

void split_insn(const std::string &insn, std::string &mnem,
                std::vector<std::string> &ops) {
    ops.clear();
    /* Los prefijos se van con el mnemonico, no delante de el: lo que hay que
     * consultar es la instruccion que modifican. */
    /* Un prefijo va CON el mnemonico, no delante como si fuera otra cosa.
     *
     * `rep stosb` se partia en mnemonico `rep` y operando `stosb`, y de ahi
     * salian los dos fallos: el bucle de operandos se atascaba en un `stosb`
     * que no es ningun operando, y a la base se le preguntaba por `rep`, que no
     * es ninguna instruccion.  Juntos, el mnemonico es `rep stosb` y la lista
     * de operandos queda vacia, que es la verdad.
     *
     * Y NO se quita aqui: este es el texto que se va a emitir, y sin el `rep`
     * la instruccion escribe un byte donde el programa pide `rcx`.  Quitarlo es
     * cosa de la consulta, que es otra cadena. */
    size_t ini = 0;
    while (true) {
        const size_t sp0 = insn.find_first_of(" \t", ini);
        if (sp0 == std::string::npos) break;
        if (!es_prefijo(trim(insn.substr(ini, sp0 - ini)))) break;
        const size_t sig = insn.find_first_not_of(" \t", sp0);
        if (sig == std::string::npos) break;
        ini = sig;
    }
    size_t sp = insn.find_first_of(" \t", ini);
    if (sp == std::string::npos) { // sin operandos
        mnem = insn;
        return;
    }
    mnem = insn.substr(0, sp);
    std::string rest = trim(insn.substr(sp + 1));
    size_t pos = 0;
    while (pos <= rest.size()) {
        size_t comma = rest.find(',', pos);
        std::string tok = rest.substr(
            pos, comma == std::string::npos ? std::string::npos : comma - pos);
        tok = trim(tok);
        if (!tok.empty()) ops.push_back(tok);
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
}

/// construye la lista PLANA de operandos de FiSICO FIJO (solo GP) y la
/// plantilla con @c $N a partir de la linea + la semantica de la DB.  Devuelve
/// @c false si algun operando NO es un registro GP nombrable (MEM/IMM/FP/VEC ->
///) -> el llamador emite @c INLINE_ASM.
/**
 * @brief El operando @c $N del cuerpo, si lo es, y su ligadura.
 *
 * @return El binding, o @c nullptr si @p tok no es un marcador.
 */
const ir::AsmRegBinding *
binding_de_marcador(const std::string &tok,
                    const std::vector<ir::AsmRegBinding> &bindings) {
    if (tok.size() < 2 || tok[0] != '$') return nullptr;
    if (tok.find_first_not_of("0123456789", 1) != std::string::npos)
        return nullptr;
    const int idx = std::atoi(tok.c_str() + 1);
    for (const ir::AsmRegBinding &b : bindings)
        if (b.reg_auto && b.ph_index == idx) return &b;
    return nullptr;
}

/**
 * @brief Descompone @c "[$N + disp]" en el marcador y el desplazamiento.
 *
 * Es la forma que deja el lowering cuando el programador escribe una direccion
 * a partir de una variable, y son 102 de los 113 bloques del corpus: casi todo
 * el ensamblador real accede a memoria por un puntero que le pasa el programa.
 *
 * Solo esta forma -- base mas desplazamiento constante -- porque es la unica en
 * la que se sabe exactamente que direccion se toca.  Con indice y escala la
 * direccion depende de otro valor, y eso es otra conversacion.
 *
 * @param tok Token completo, corchetes incluidos.
 * @param marcador Recibe el @c "$N".
 * @param disp Recibe el desplazamiento (0 si no lleva).
 * @return @c false si no es esa forma.
 */
bool partir_memoria_marcador(const std::string &tok, std::string &marcador,
                             int64_t &disp) {
    if (tok.size() < 3 || tok.front() != '[' || tok.back() != ']') return false;
    std::string in = trim(tok.substr(1, tok.size() - 2));
    disp = 0;
    size_t sig = in.find_first_of("+-");
    if (sig == std::string::npos) {
        marcador = in;
    } else {
        marcador = trim(in.substr(0, sig));
        std::string resto = trim(in.substr(sig + 1));
        if (resto.empty()) return false;
        /* El desplazamiento puede traer su propio signo: el lowering escribe
         * `[$0 + -0x40]`, con el signo del numero aparte del de la suma.  Se
         * combinan los dos.  Rechazarlo por el segundo signo dejaba fuera un
         * tercio de los accesos, todos los que van hacia atras. */
        int signo = (in[sig] == '-') ? -1 : 1;
        while (!resto.empty() && (resto[0] == '+' || resto[0] == '-')) {
            if (resto[0] == '-') signo = -signo;
            resto = trim(resto.substr(1));
        }
        // Un operador mas alla del numero significa indice o escala.
        if (resto.find_first_of("+-*") != std::string::npos) return false;
        char *fin = nullptr;
        const long long v = std::strtoll(resto.c_str(), &fin, 0);
        if (fin == nullptr || *fin != '\0') return false;
        disp = (int64_t)v * signo;
    }
    return marcador.size() >= 2 && marcador[0] == '$' &&
           marcador.find_first_not_of("0123456789", 1) == std::string::npos;
}

/// Ancho en bits del operando que declaro el programador ("reg" -> el del
/// tipo).
uint16_t ancho_declarado(const ir::AsmRegBinding &b) {
    if (b.reg_class == "zmm") return 512;
    if (b.reg_class == "ymm") return 256;
    if (b.reg_class == "xmm") return 128;
    // Una clase vectorial declara su ancho por si misma (arriba); el resto lo
    // saca del eje de RANURA del vocabulario unico, que es el que habla de
    // registros.  Aqui vivia otra copia de esa tabla, en bits.
    return static_cast<uint16_t>(ir::type_slot_bytes(b.type) * 8u);
}

bool build_operands(
    instr_db::Isa isa, const std::string &insn, const instr_db::AsmInsnSem &sem,
    const std::unordered_map<std::string, ir::IrValueId> &slot_of,
    const std::vector<ir::AsmRegBinding> &bindings,
    std::vector<ir::AsmMicroOperand> &operands, std::string &tmpl,
    AsmMotivoOpaco *motivo) {
    operands.clear();
    std::string mnem;
    std::vector<std::string> toks;
    split_insn(insn, mnem, toks);
    if (toks.empty()) {
        /* Sin operandos ESCRITOS hay dos situaciones distintas, y tratarlas
         * igual dejaba fuera a un grupo entero de instrucciones.
         *
         * Una es que no se haya reconocido lo que hay, y ahi si hay que
         * rendirse.  La otra es que no haya nada que reconocer porque la
         * instruccion no lleva operandos en el texto: `rep movsb` los tiene
         * TODOS implicitos -- origen, destino y contador --, y la base los
         * sabe.  Rechazarla por "no se le reconocio ningun operando" era
         * confundir "no hay" con "no se pudo": la instruccion quedaba opaca y
         * con ella se perdian las ligaduras de sus registros.
         *
         * Que la forma exista y no declare ninguno explicito es justamente la
         * senal de que estamos en el segundo caso. */
        bool lee = false, escribe = false;
        const bool tiene_explicitos =
            sem.form_id >= 0 &&
            instr_db::explicit_operand(isa, sem.form_id, 0, lee, escribe);
        if (tiene_explicitos)
            return AsmMotivoOpaco::anotar(motivo, insn, "VXA022");
        tmpl = mnem;
        return true;
    }

    tmpl = mnem;
    for (size_t k = 0; k < toks.size(); ++k) {
        /* Un operando `$N` es una variable del programa a la que todavia no se
         * le ha dado registro: el programador escribio la CLASE y dejo elegir
         * al compilador.  Es, literalmente, un pseudo-registro -- y es el 87%
         * de los bloques del corpus, asi que mientras no entre por aqui el
         * elevado no llega a casi ningun asm real.
         *
         * No se le pone fisico: se queda a -1 y lo reparte el asignador, que es
         * quien puede.  Lo que si lleva es el VALOR, que es lo que hace que el
         * dato entre y salga del bloque. */
        /* La otra cara de lo mismo: una direccion formada a partir de una
         * variable, `[$0 + 8]`.  El operando es memoria y la BASE es el valor;
         * el desplazamiento es constante y viaja con el.  Aqui se rompio el
         * primer intento: trataba la base como un registro con nombre, y la
         * base es un marcador -- el nombre no existe todavia. */
        /* Un inmediato es un numero escrito en el propio asm: no depende de
         * nada y no hay a quien preguntarle.  Va en la ficha como operando
         * para que la lista siga cuadrando con las posiciones de la forma. */
        {
            const std::string &t = toks[k];
            char *fin = nullptr;
            const long long v = std::strtoll(t.c_str(), &fin, 0);
            const bool es_numero = !t.empty() && fin != nullptr &&
                                   *fin == '\0' &&
                                   (std::isdigit((unsigned char)t[0]) ||
                                    t[0] == '-' || t[0] == '+');
            if (es_numero) {
                // Parte del camino nuevo: mientras este detras del interruptor,
                // lo esta entero.  Que el defecto sea EXACTAMENTE lo de antes
                // es lo unico que hace comparable una cosa con la otra.
                if (!elevar_ligados())
                    return AsmMotivoOpaco::anotar(motivo, insn, "VXA023", {t});
                ir::AsmMicroOperand op;
                op.kind = ir::AsmOperandKind::IMM;
                op.imm = (int64_t)v;
                op.fixed_phys = -1;
                op.value = ir::IR_NO_VALUE;
                op.flags = ir::ASM_OP_READ;
                operands.push_back(op);
                tmpl += (k == 0 ? " $" : ", $") + std::to_string(k);
                continue;
            }
        }
        std::string marc;
        int64_t disp = 0;
        const ir::AsmRegBinding *bmem = nullptr;
        if (partir_memoria_marcador(toks[k], marc, disp))
            bmem = binding_de_marcador(marc, bindings);
        if (bmem != nullptr) {
            if (!elevar_ligados())
                return AsmMotivoOpaco::anotar(motivo, insn, "VXA023",
                                              {toks[k]});
            if (bmem->is_vector) // una direccion no se forma con el banco ancho
                return AsmMotivoOpaco::anotar(motivo, insn, "VXA023",
                                              {toks[k]});
            ir::AsmMicroOperand op;
            op.kind = ir::AsmOperandKind::MEM;
            op.regclass = vx::ASM_RC_GP; // clase de la BASE
            op.width = 64;               // una direccion, no el dato
            op.fixed_phys = -1;
            op.value = bmem->alloca_value;
            op.imm = disp;
            /* La BASE siempre se lee: hay que tenerla para formar la direccion,
             * escriba la instruccion en esa memoria o no.  Que la MEMORIA se
             * lea o se escriba es otra cosa, y va en el byte de efectos. */
            op.flags = ir::ASM_OP_READ;
            operands.push_back(op);
            /* La plantilla lleva el marcador PELADO, sin corchetes: que un
             * operando sea una direccion lo dice la ficha, y como se escribe
             * una direccion lo sabe el nombrador de la ISA.  Escribirla aqui la
             * ata a x86 y ademas la ponia dos veces -- salia `[[r15]]`, que no
             * ensambla, y como un bloque que no ensambla no emite nada, el
             * programa se quedaba sin ese trozo sin decir palabra. */
            tmpl += (k == 0 ? " $" : ", $") + std::to_string(k);
            continue;
        }
        if (const ir::AsmRegBinding *b =
                binding_de_marcador(toks[k], bindings)) {
            if (!elevar_ligados())
                return AsmMotivoOpaco::anotar(motivo, insn, "VXA028");
            /* El banco ancho, todavia no -- y el motivo ya no es el que era.
             *
             * El contexto del trampolin YA lo lleva (se amplio), asi que el
             * interprete puede ejecutar la instruccion.  Lo que falta es meter
             * y sacar esos valores: los emisores pasan los operandos por una
             * tabla de enteros, y un registro ancho no cabe ahi.  Comprobado
             * quitando este bail: el caso vectorial falla en los dos motores.
             *
             * Sigue siendo una carencia de los motores, no del modelo -- el ASA
             * describe estos registros igual que los demas --, pero vive aqui
             * porque es aqui donde se decide que se eleva. */
            ir::AsmMicroOperand op;
            /* El banco ancho sigue sin subir, y ahora se sabe exactamente que
             * falta.  El reparto de registros ya no es el problema -- se hace
             * por clase, y `xmm0` no estorba a `rax` --, ni el nombrado, que ya
             * sabe escribir xmm/ymm/zmm.  Lo que falta esta en los MOTORES:
             * meter y sacar el valor.  Medido quitando este bail: la e2e cae en
             * 4 casos (import_std_memory, instr_no_soportada,
             * std_memory_variantes, asm_examples).
             *
             * Y el precio de que siga puesto conviene tenerlo escrito: un solo
             * operando ancho deja opaco el BLOQUE ENTERO, y de un bloque opaco
             * no sale ninguna exigencia de alineacion -- justo lo que estas
             * instrucciones EXIGEN. */
            op.kind = ir::AsmOperandKind::REG;
            op.regclass = b->is_vector ? vx::ASM_RC_VEC : vx::ASM_RC_GP;
            /* Y si el registro es mas ancho de lo que cabe en el contexto, este
             * bloque se queda opaco A PROPOSITO.  Moverlo a medias no da error:
             * deja medio valor, y el programa sigue con la otra mitad de antes.
             * Pasa con SVE (hasta 2048 bits) y con RVV, que ni siquiera tiene
             * tope fijo. */
            if (b->is_vector && !vx::asm_cabe_en_ranura(ancho_declarado(*b)))
                return AsmMotivoOpaco::anotar(motivo, insn, "VXA023",
                                              {toks[k]});
            op.width = ancho_declarado(*b);
            op.fixed_phys = -1; // lo elige el asignador
            op.value = b->alloca_value;
            bool lee = false, escribe = false;
            uint8_t fl = 0;
            if (instr_db::explicit_operand(isa, sem.form_id, k, lee, escribe)) {
                if (lee) fl |= ir::ASM_OP_READ;
                if (escribe) fl |= ir::ASM_OP_WRITE;
            }
            if (fl == 0) return AsmMotivoOpaco::anotar(motivo, insn, "VXA025");
            op.flags = fl;
            operands.push_back(op);
            tmpl += (k == 0 ? " $" : ", $") + std::to_string(k);
            continue;
        }
        uint16_t w = 0;
        uint8_t clase = vx::ASM_RC_GP;
        int phys = vx::asm_x86_gp_index(toks[k], &w);
        if (phys < 0) {
            /* Y del banco ANCHO.
             *
             * Solo se aceptaban registros generales, asi que un `movdqa xmm1,
             * xmm0` -- que es exactamente el caso que DEBE quedarse como micro
             * asm, porque es especifico de la ISA y nunca sera IR -- se caia al
             * camino opaco por no saber leer el nombre de su registro.  El
             * modelo ya tiene la clase vectorial; faltaba el inverso del
             * nombrador. */
            phys = vx::asm_x86_vec_index(toks[k], &w);
            if (phys >= 0) clase = vx::ASM_RC_VEC;
        }
        if (phys < 0) {
            /* Una instruccion de salto no se atasca en un operando: es que el
             * micro asm modela INSTRUCCIONES, y el flujo de control no es de
             * una instruccion, es del grafo.  De eso se ocupa el elevado
             * general. Decirlo como "operando que no pasa a IR" manda a
             * arreglar donde no es.
             *
             * Quien sabe si una linea es un salto es el clasificador del ASA, y
             * lo sabe POR ISA: `jmp` y `b` y `cbz` son la misma cosa en tres
             * juegos de instrucciones distintos.  Mirar el mnemonico aqui seria
             * escribir x86 en un sitio que no es de ninguna arquitectura. */
            std::string destino;
            const AsmTerm t = asm_classify_term(isa, insn, destino);
            if (t != AsmTerm::Fallthrough)
                return AsmMotivoOpaco::anotar(motivo, insn, "VXA035",
                                              {toks[k]});
            return AsmMotivoOpaco::anotar(motivo, insn, "VXA023", {toks[k]});
        }
        ir::AsmMicroOperand op;
        op.kind = ir::AsmOperandKind::REG;
        op.regclass = clase;
        op.width = w;
        op.fixed_phys = (int16_t)phys; // fisico fijo del texto (constraint RA)
        /* Un registro LIGADO con `register()` no es un registro opaco: es una
         * variable del programa, y lo que tiene que viajar es su VALOR.  El
         * registro que escribio el usuario se conserva como PIN -- lo pidio por
         * algo, y muchas veces es una convencion (el numero de llamada al
         * sistema va en rax) -- pero el valor va por el IR, que es lo que
         * permite que el interprete lo meta y lo saque del bloque y que el
         * asignador sepa que ese registro esta ocupado. */
        const auto lig = slot_of.find(lower(toks[k]));
        if (lig != slot_of.end()) {
            if (!elevar_ligados())
                return AsmMotivoOpaco::anotar(motivo, insn, "VXA024");
            op.value = lig->second;
        } else {
            op.value = ir::IR_NO_VALUE; // fisico opaco (sin SSA)
        }
        /* Rol del operando: lo dice la FORMA, por posicion.
         *
         * Se estaba deduciendo buscando el nombre del registro en las listas de
         * lectura y escritura de la instruccion, y eso solo funciona con los
         * generales: para `movdqa xmm1, xmm0` no encontraba nada y la
         * instruccion acababa pareciendo que no toca ningun registro -- o sea,
         * el bloque entero se caia al camino opaco por no saber leer su propio
         * modelo.  La forma lo dice por posicion y vale para cualquier clase.
         *
         * El nombre se conserva como respaldo: cubre los casos en que la forma
         * no distingue (operandos implicitos que si aparecen escritos). */
        const std::string cn = lower(toks[k]);
        uint8_t fl = 0;
        bool lee = false, escribe = false;
        if (instr_db::explicit_operand(isa, sem.form_id, k, lee, escribe)) {
            if (lee) fl |= ir::ASM_OP_READ;
            if (escribe) fl |= ir::ASM_OP_WRITE;
        }
        if (fl == 0) {
            if (has_reg(sem.reads, cn)) fl |= ir::ASM_OP_READ;
            if (has_reg(sem.writes, cn)) fl |= ir::ASM_OP_WRITE;
        }
        if (fl == 0) return AsmMotivoOpaco::anotar(motivo, insn, "VXA025");
        op.flags = fl;
        operands.push_back(op);
        tmpl += (k == 0 ? " $" : ", $") + std::to_string(k);
    }
    return true;
}

/**
 * @brief Anota en la ficha los registros que la instruccion toca por
 *        CONVENCION, no por nombre.
 *
 * `cpuid` escribe rax, rbx, rcx y rdx sin que ninguno aparezca escrito en la
 * linea.  Para el que asigna registros eso es indistinguible de escribirlos:
 * si no lo sabe, deja ahi un valor vivo y la instruccion lo pisa.  El modelo ya
 * tenia la marca (@c ASM_OP_IMPLICIT) y nadie la llenaba.
 *
 * Van DETRAS de los explicitos para no mover los @c $N de la plantilla, que se
 * indexan por posicion.
 *
 * @param arch Arquitectura para consultar los efectos ("x86_64" / "arm64").
 * @param insn Instruccion completa.
 * @param operands Lista de operandos a completar.
 * @return @c false si algun registro implicito no se supo nombrar -- en ese
 *         caso no se puede prometer que la ficha este completa.
 */
bool anotar_implicitos(const std::string &arch, const std::string &insn,
                       std::vector<ir::AsmMicroOperand> &operands,
                       AsmMotivoOpaco *motivo) {
    const size_t sp = insn.find_first_of(" \t");
    const std::string mnem =
        (sp == std::string::npos) ? insn : insn.substr(0, sp);
    const vx::AsmEffects ef = vx::asm_effects_for(mnem, arch);
    for (int fase = 0; fase < 2; ++fase) {
        const std::vector<std::string> &lista =
            (fase == 0) ? ef.implicit_read : ef.implicit_write;
        for (const std::string &r : lista) {
            uint16_t w = 0;
            uint8_t clase = vx::ASM_RC_GP;
            int phys = vx::asm_x86_gp_index(r, &w);
            if (phys < 0) {
                phys = vx::asm_x86_vec_index(r, &w);
                if (phys >= 0) clase = vx::ASM_RC_VEC;
            }
            if (phys < 0) {
                /* Los flags ya viajan en el byte de efectos, asi que no hacen
                 * falta como operando; cualquier otro nombre que no se sepa
                 * nombrar si es un hueco, y un hueco aqui significa un registro
                 * destruido del que nadie se entera. */
                const std::string rl = lower(r);
                if (rl == "flags" || rl == "eflags" || rl == "rflags" ||
                    rl == "nzcv" || rl == "memory")
                    continue;
                return AsmMotivoOpaco::anotar(motivo, insn, "VXA026", {r});
            }
            ir::AsmMicroOperand op;
            op.kind = ir::AsmOperandKind::REG;
            op.regclass = clase;
            op.width = w;
            op.fixed_phys = (int16_t)phys;
            op.value = ir::IR_NO_VALUE;
            op.flags = ir::ASM_OP_IMPLICIT |
                       (fase == 0 ? ir::ASM_OP_READ : ir::ASM_OP_WRITE);
            operands.push_back(op);
        }
    }
    return true;
}

} // namespace

bool asm_lift_micro(
    ir::IrFunction &fn, uint32_t block, instr_db::Isa isa,
    const std::string &body, uint32_t line,
    const std::unordered_map<std::string, ir::IrValueId> &slot_of,
    AsmMotivoOpaco *motivo, uint32_t *bloque_salida) {
    /* Por donde sigue la ejecucion.  Hoy, el mismo bloque en el que se emite:
     * un asm sin saltos empieza y acaba donde estaba.  Se contesta ANTES de
     * cualquier salida para que quien pregunte tenga respuesta tambien cuando
     * el bloque no se puede elevar -- ahi la ejecucion sigue igualmente, con el
     * asm como caja, y el llamante necesita saber donde. */
    if (bloque_salida != nullptr) *bloque_salida = block;
    const std::vector<std::string> insns = instructions(body);
    if (insns.empty())
        return AsmMotivoOpaco::anotar(motivo, std::string(), "VXA027");

    // Microarq para la semantica: solo usamos los campos SEMaNTICOS (form_id,
    // barrera, mem, flags, reads/writes), no la latencia, asi que cualquier
    // microarq valida de la ISA sirve.  Skylake para x86; fallback 0.
    int32_t ua = instr_db::microarch_by_name(isa, "intel-skylake");
    if (ua < 0) ua = 0;

    // Fase 1 (validacion transaccional): TODAS las instrucciones deben ser
    // formas conocidas por la DB, y O BIEN sin operandos de registro (mfence,
    // cpuid, ...), O BIEN con operandos de FiSICO FIJO GP (: popcnt/tzcnt/
    // bswap rax,...).  Cualquier otra cosa (MEM/IMM/FP/VEC/implicitos,)
    // -> false y el llamador emite INLINE_ASM.
    std::vector<instr_db::AsmInsnSem> sems;
    std::vector<std::vector<ir::AsmMicroOperand>> ops_per;
    std::vector<std::string> tmpl_per;
    sems.reserve(insns.size());
    ops_per.reserve(insns.size());
    tmpl_per.reserve(insns.size());
    // ASA: arch string para consultar los efectos IMPLICITOS (asm_effects).  La
    // DB de instrucciones (instr_db) modela la SEMANTICA de la forma (operandos
    // explicitos), pero NO los registros que una instruccion lee/escribe por
    // convencion de ABI: `syscall` lee el numero en RAX y los args en
    // RDI/RSI/RDX/R10/R8/R9; `int` lee EAX+args; `svc` lee X8+X0..X7.
    const std::string arch_s =
        (isa == instr_db::Isa::ARM64) ? "arm64" : "x86_64";
    // Registros fisicos que el propio bloque ha escrito hasta ahora, como
    // (clase << 16) | indice.  Leer uno que no este aqui es leer de fuera.
    std::set<uint32_t> escritos_del_bloque;
    for (const std::string &insn : insns) {
        /* Un operando que todavia es un MARCADOR (`$0`) es una variable del
         * programa a la que el asignador aun no ha dado registro.  Trocear no
         * sabe enhebrarlas, asi que el bloque se queda entero -- ahi si se
         * resuelven.  Hay que mirarlo ANTES de preguntar a la base de datos:
         * un marcador no es un operando que ella pueda clasificar, asi que
         * casa una forma que no es y la instruccion acaba pareciendo que no
         * lee ni escribe registros.  El guardia de mas abajo no lo cubre --
         * ese busca el NOMBRE del registro, y aqui todavia no hay ninguno. */
        /* La base de instrucciones clasifica una linea por sus operandos, y un
         * marcador no lo es: con `$0` dentro casa una forma que no es, y la
         * instruccion acaba pareciendo que no lee ni escribe registros.
         *
         * Se le pregunta, entonces, por una linea EQUIVALENTE: el marcador
         * sustituido por un registro de su misma clase y ancho.  Cual sea da
         * igual -- la forma depende de la clase, no del numero -- y el registro
         * de verdad lo elegira el asignador.  Antes de esto el bloque se
         * abandonaba aqui sin llegar a preguntar. */
        std::string consulta = insn;
        {
            std::string mnem_ph;
            std::vector<std::string> toks_ph;
            split_insn(insn, mnem_ph, toks_ph);
            for (const std::string &t : toks_ph) {
                // Una direccion se le presenta como direccion: el marcador de
                // la base por un registro cualquiera, el resto igual.
                std::string mm;
                int64_t dd = 0;
                if (partir_memoria_marcador(t, mm, dd) &&
                    binding_de_marcador(mm, fn.asm_reg_bindings) != nullptr) {
                    if (!elevar_ligados())
                        return AsmMotivoOpaco::anotar(motivo, insn, "VXA023",
                                                      {t});
                    const std::string rep = vx::asm_mem_operando(
                        (uint8_t)isa,
                        vx::asm_reg_muestra((uint8_t)isa, vx::ASM_RC_GP, 64),
                        dd);
                    if (rep.empty())
                        return AsmMotivoOpaco::anotar(motivo, insn, "VXA023",
                                                      {t});
                    const size_t p = consulta.find(t);
                    if (p != std::string::npos)
                        consulta.replace(p, t.size(), rep);
                    continue;
                }
                const ir::AsmRegBinding *b =
                    binding_de_marcador(t, fn.asm_reg_bindings);
                if (b == nullptr) {
                    // Marcador sin ligadura: no se sabe ni de que clase es.
                    if (t.size() >= 2 && t[0] == '$' &&
                        t.find_first_not_of("0123456789", 1) ==
                            std::string::npos)
                        return AsmMotivoOpaco::anotar(motivo, insn, "VXA028");
                    continue;
                }
                if (!elevar_ligados())
                    return AsmMotivoOpaco::anotar(motivo, insn, "VXA028");
                const std::string rep = vx::asm_reg_muestra(
                    (uint8_t)isa, b->is_vector ? vx::ASM_RC_VEC : vx::ASM_RC_GP,
                    ancho_declarado(*b));
                if (rep.empty())
                    return AsmMotivoOpaco::anotar(motivo, insn, "VXA028");
                const size_t p = consulta.find(t);
                if (p != std::string::npos) consulta.replace(p, t.size(), rep);
            }
        }
        /* A la base se le pregunta por la INSTRUCCION, no por su prefijo.
         *
         * `rep stosb` se le presentaba tal cual, y lo leia como un mnemonico
         * `rep` con un operando `stosb`: no reconocia ninguno de los dos y la
         * daba por desconocida.  La base SI tiene `stosb` -- lo que estaba mal
         * era la pregunta.
         *
         * Y se quita AQUI y no antes porque el texto que se emite tiene que
         * conservarlo: sin el `rep`, `stosb` escribe un byte donde el programa
         * pide `rcx`.  Son dos cadenas con dos usos, y confundirlas cambia lo
         * que hace el programa.
         *
         * Con la consulta acertando, la instruccion deja de ser OPACA: sus
         * efectos -- que toca memoria, que lee el contador -- salen de la base
         * como los de cualquier otra.  Que la repeticion no se convierta en
         * operaciones del IR es otra cosa: no elevarla no es no conocerla, y
         * tratarlo igual tiraba informacion que si teniamos. */
        /* Se pregunta por la linea ENTERA, con su prefijo.  La base junta las
         * dos partes ella misma -- `rep movsb` es `rep_movsb`, otra forma -- y
         * esa forma es la que sabe que se lee y se escribe el contador.
         *
         * Antes se le quitaba el prefijo antes de preguntar, y la respuesta era
         * la de `movsb` a secas, que no mira `rcx`.  Con eso, una variable
         * ligada a `rcx` no la leia nadie: el optimizador la borraba por muerta
         * y el bloque arrancaba con lo que hubiera en el registro.  Se veia
         * como `memcpy_erms` copiando basura, o sin terminar nunca.
         *
         * Si la forma con prefijo no esta en la base se vuelve a preguntar sin
         * el: perder el contador es peor que quedarse opaco, pero quedarse
         * opaco sin necesidad tambien es perder. */
        std::string consulta_sin_prefijo = consulta;
        {
            size_t ini = 0;
            while (true) {
                const size_t sp0 =
                    consulta_sin_prefijo.find_first_of(" \t", ini);
                if (sp0 == std::string::npos) break;
                if (!es_prefijo(
                        trim(consulta_sin_prefijo.substr(ini, sp0 - ini))))
                    break;
                const size_t sig =
                    consulta_sin_prefijo.find_first_not_of(" \t", sp0);
                if (sig == std::string::npos) break;
                ini = sig;
            }
            if (ini != 0)
                consulta_sin_prefijo = consulta_sin_prefijo.substr(ini);
        }
        instr_db::AsmInsnSem sem =
            instr_db::asm_insn_sem(isa, consulta, (uint32_t)ua);
        if (sem.form_id < 0 && consulta_sin_prefijo != consulta)
            sem =
                instr_db::asm_insn_sem(isa, consulta_sin_prefijo, (uint32_t)ua);
        if (sem.form_id < 0) { // desconocida por la DB
            anotar_hueco_db(insn, "la base de datos no conoce esta forma");
            return AsmMotivoOpaco::anotar(motivo, insn, "VXA029");
        }
        // Si la instruccion LEE/ESCRIBE implicitamente un registro que esta
        // LIGADO a una variable Vesta (register(): p.ej. `syscall` con
        // register("rax") id + register("rdi") a1 en los params del invoke), el
        // asm_micro NO puede modelar esos operandos implicitos (solo trocea los
        // textuales) -> los args no se threadean, el RA no los coloca y el DCE
        // elimina sus stores.  Lo dejamos al INLINE_ASM, que SI marca los
        // bindings como in/out vregs y respeta el pin al registro fisico.
        {
            /* Se pregunta por la LINEA, no por su primera palabra.  Cortando
             * por el primer espacio, `rep movsb` preguntaba por `rep` -- que no
             * es una instruccion y no tiene efectos --, asi que no se veia que
             * toca `rsi`, `rdi` y `rcx`: se micro-elevaba, las ligaduras de
             * esos tres se quedaban sin nadie que las leyera y el optimizador
             * las borraba.  El bloque arrancaba con lo que hubiera en los
             * registros.
             *
             * Y se miran las CUATRO listas.  Un registro por el que se accede a
             * memoria esta tan ligado como cualquier otro: `movsb` lee por
             * `rsi` y escribe por `rdi`, y eso vive en su propia lista porque
             * dice POR DONDE, no QUE. */
            std::string mnem_ef;
            {
                const size_t sp1 = insn.find_first_of(" \t");
                mnem_ef =
                    (sp1 == std::string::npos) ? insn : insn.substr(0, sp1);
                /* Un prefijo de repeticion no es la instruccion: se une con la
                 * que viene detras, que es como la nombra la base. */
                if (sp1 != std::string::npos && es_prefijo(trim(mnem_ef))) {
                    const size_t ini = insn.find_first_not_of(" \t", sp1);
                    if (ini != std::string::npos) {
                        const size_t sp2 = insn.find_first_of(" \t", ini);
                        mnem_ef = (sp2 == std::string::npos)
                                      ? insn.substr(ini)
                                      : insn.substr(ini, sp2 - ini);
                    }
                }
            }
            vx::AsmEffects ef = vx::asm_effects_for(mnem_ef, arch_s);
            bool binds_implicit = false;
            for (const std::vector<std::string> *lista :
                 {&ef.implicit_read, &ef.implicit_write, &ef.implicit_mem_read,
                  &ef.implicit_mem_write}) {
                for (const std::string &r : *lista)
                    if (slot_of.find(lower(r)) != slot_of.end()) {
                        binds_implicit = true;
                        break;
                    }
                if (binds_implicit) break;
            }
            if (binds_implicit)
                return AsmMotivoOpaco::anotar(motivo, insn, "VXA030");
        }
        std::vector<ir::AsmMicroOperand> operands;
        std::string tmpl;
        // Una instruccion con operandos ESCRITOS pasa siempre por el analisis
        // de operandos, aunque la DB no describa su forma.  Copiarla verbatim
        // por esa via -- que es lo que se hacia -- la convierte en opaca y
        // pierde de vista que uno de esos operandos es una variable del
        // programa: la instruccion se ejecutaba sobre un registro cualquiera y
        // el valor no volvia.  Sin la forma en la DB no se puede saber que
        // hace con cada uno, asi que se deja al bloque con ligaduras.
        std::string mnem_tmp;
        std::vector<std::string> toks_tmp;
        split_insn(insn, mnem_tmp, toks_tmp);
        if (toks_tmp.empty() && sem.reads.empty() && sem.writes.empty()) {
            // Sin operandos de registro: plantilla verbatim
            // (mfence/lfence/...).
            tmpl = insn;
        } else {
            if (!toks_tmp.empty() && sem.reads.empty() && sem.writes.empty()) {
                anotar_hueco_db(insn, "la forma esta en la base de datos pero "
                                      "no dice que registros lee o escribe");
            }
            if (!build_operands(isa, insn, sem, slot_of, fn.asm_reg_bindings,
                                operands, tmpl, motivo))
                return false; // build_operands ya dejo dicho el motivo
        }
        // Lo que la instruccion toca por convencion cuenta igual: el asignador
        // no distingue un registro destruido por nombre de uno destruido por
        // ABI.  Tambien para las que no llevan operandos escritos (cpuid).
        if (!anotar_implicitos(arch_s, insn, operands, motivo)) return false;

        /* Un registro que la instruccion LEE y que el bloque no ha escrito
         * antes viene de fuera, y de fuera no llega.
         *
         * El interprete ejecuta cada una de estas en un trampolin propio que
         * pone los registros generales a cero y ni siquiera toca el banco
         * ancho, asi que leer algo de fuera del bloque es leer basura.  En el
         * JIT y en el AOT si llega -- los bytes van dentro de la funcion -- y
         * esa diferencia entre modos es precisamente lo que no puede pasar.
         *
         * Hoy no se notaba porque un bloque elevado no puede comunicar nada al
         * programa: no acepta operandos ligados ni memoria.  O sea que solo era
         * correcto por ser inofensivo.  En cuanto se le deje tocar memoria deja
         * de serlo, asi que se corta aqui y no cuando ya haya dado un resultado
         * equivocado.
         *
         * Esto lo levanta el paso a valores SSA: cuando el operando deje de ser
         * un nombre de registro y sea un valor, no habra nada que venga "de
         * fuera" -- lo trae el propio IR. */
        for (const ir::AsmMicroOperand &op : operands) {
            if (!op.reads() || op.fixed_phys < 0) continue;
            // Un operando ligado SI llega: su valor entra por el IR.
            if (op.value != ir::IR_NO_VALUE) continue;
            const uint32_t clave =
                ((uint32_t)op.regclass << 16) | (uint32_t)op.fixed_phys;
            if (escritos_del_bloque.count(clave) != 0) continue;
            const std::string nom = vx::asm_phys_reg_name(
                (uint8_t)isa, op.regclass, op.fixed_phys,
                op.width != 0
                    ? op.width
                    : (uint16_t)(op.regclass == vx::ASM_RC_GP ? 64 : 128));
            return AsmMotivoOpaco::anotar(
                motivo, insn, "VXA031", {nom.empty() ? std::string("?") : nom});
        }
        for (const ir::AsmMicroOperand &op : operands) {
            if (!op.writes() || op.fixed_phys < 0) continue;
            escritos_del_bloque.insert(((uint32_t)op.regclass << 16) |
                                       (uint32_t)op.fixed_phys);
        }
        sems.push_back(std::move(sem));
        ops_per.push_back(std::move(operands));
        tmpl_per.push_back(std::move(tmpl));
    }

    /* Una variable ligada vive en un hueco, y lo que el asm necesita es su
     * VALOR, no la direccion del hueco.  Es la convencion que ya sigue el
     * elevado general -- "el lift la modela leyendo y escribiendo el slot" -- y
     * saltarsela fue exactamente el fallo: pasar el hueco como si fuera el
     * valor hacia que `mov [d], b` escribiera dentro del propio hueco en vez de
     * donde apuntaba, y la variable se quedaba a cero.
     *
     * Se carga UNA vez por bloque y por variable: dos instrucciones que usen la
     * misma comparten el valor, que es lo que hace que entre y salga una sola
     * vez.  Lo que el bloque ESCRIBE se devuelve al hueco al final. */
    std::unordered_map<ir::IrValueId, ir::IrValueId> valor_de_hueco;
    std::vector<ir::IrValueId> huecos_escritos;
    auto valor_del_hueco = [&](ir::IrValueId hueco, bool host) {
        auto it = valor_de_hueco.find(hueco);
        if (it != valor_de_hueco.end()) return it->second;
        const ir::IrValueId v = fn.new_value(ir::IrType::I64);
        ir::IrInstr ld{};
        ld.op = ir::IrOp::LOAD;
        ld.type = ir::IrType::I64;
        ld.dst = v;
        ld.operands = {hueco};
        ld.source_line = line;
        fn.append(block, std::move(ld));
        if (host) fn.values[v].is_host_ptr = true;
        valor_de_hueco.emplace(hueco, v);
        return v;
    };
    for (auto &ops : ops_per)
        for (ir::AsmMicroOperand &op : ops) {
            if (op.value == ir::IR_NO_VALUE) continue;
            const ir::IrValueId hueco = op.value;
            op.value =
                valor_del_hueco(hueco, op.kind == ir::AsmOperandKind::MEM);
            if (op.writes() && op.kind != ir::AsmOperandKind::MEM) {
                bool ya = false;
                for (ir::IrValueId h : huecos_escritos)
                    if (h == hueco) {
                        ya = true;
                        break;
                    }
                if (!ya) huecos_escritos.push_back(hueco);
            }
        }

    // Fase 2 (emision): una ASM_MICRO por instruccion.
    for (size_t i = 0; i < insns.size(); ++i) {
        ir::AsmMicro am;
        am.isa = (uint8_t)isa;
        am.form_id = (uint32_t)sems[i].form_id;
        am.tmpl = std::move(tmpl_per[i]);
        am.operands = std::move(ops_per[i]);
        am.eff = pack_eff(sems[i]);

        ir::IrInstr in{};
        in.op = ir::IrOp::ASM_MICRO;
        in.type = ir::IrType::VOID;
        in.dst = ir::IR_NO_VALUE;
        in.imm = fn.asm_micros.size();
        in.source_line = line;
        /* Los valores que la instruccion toca se declaran como operandos de la
         * instruccion IR, no solo dentro de la ficha.  Los pases miran los
         * operandos: un valor que solo consta en la ficha no lo ve nadie, y el
         * primer pase que limpie lo que no se usa se lo lleva por delante. */
        for (const ir::AsmMicroOperand &op : am.operands)
            if (op.value != ir::IR_NO_VALUE) in.operands.push_back(op.value);
        fn.asm_micros.push_back(std::move(am));
        fn.append(block, std::move(in));
    }
    /* Y lo que el bloque cambio vuelve a su hueco.  El valor es el MISMO que se
     * cargo: para el backend ese valor es un registro y el asm lo modifica ahi
     * mismo, igual que en el camino opaco.  Sin este paso la variable conserva
     * lo de antes y el `inc` del programa no se ve desde fuera del bloque. */
    for (ir::IrValueId hueco : huecos_escritos) {
        const auto it = valor_de_hueco.find(hueco);
        if (it == valor_de_hueco.end()) continue;
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = ir::IrType::I64;
        st.operands = {it->second, hueco};
        st.source_line = line;
        fn.append(block, std::move(st));
    }
    return true;
}

std::vector<std::pair<std::string, std::string>> asm_db_huecos() {
    std::lock_guard<std::mutex> g(huecos_db_mutex());
    return {huecos_db().begin(), huecos_db().end()};
}

} // namespace vx
