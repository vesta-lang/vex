/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file asm_analyze.cpp
 * @brief Implementacion del resumen de efectos de bloque de un inline asm
 *        (ver asm_analyze.h).
 */
#include "vx/asm/asm_analyze.h"

#include <cctype>
#include <cstdlib>
#include <set>

#include "vx/asm/asm_effects.h"

#include <unordered_map>

namespace vx {

namespace {

/// Pasa @p s a minusculas (ASCII).
std::string lower(const std::string &s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s)
        o.push_back(static_cast<char>(std::tolower((unsigned char)c)));
    return o;
}

/// Trocea una linea NASM en tokens: separadores whitespace y coma; los
/// corchetes/operandos se mantienen como tokens sueltos (basta para detectar
/// el mnemonico y los registros; el analisis fino de operandos es trabajo
/// posterior (reconstruccion de CFG + dataflow).
std::vector<std::string> tokenize_line(const std::string &line) {
    std::vector<std::string> out;
    std::string cur;
    auto flush = [&] {
        if (!cur.empty()) {
            out.push_back(cur);
            cur.clear();
        }
    };
    for (char c : line) {
        if (std::isspace((unsigned char)c) || c == ',') {
            flush();
        } else {
            cur.push_back(c);
        }
    }
    flush();
    return out;
}

/**
 * @brief Trocea los OPERANDOS de una linea, respetando los corchetes.
 *
 * Hace falta para saber QUE operando es el de memoria, y con ello si la
 * instruccion lo lee o lo escribe.  No vale trocear por comas a secas: la coma
 * de `[rbx + rcx*8]` pertenece al modo de direccionamiento, no separa
 * operandos.
 *
 * @param linea Linea completa, ya sin comentarios.
 * @param mnem  Mnemonico en minusculas, tal como se reconocio.
 * @return Los operandos en orden textual, sin espacios alrededor.
 */
std::vector<std::string> operandos_de(const std::string &linea,
                                      const std::string &mnem) {
    std::vector<std::string> out;
    // Situarse justo detras del mnemonico (comparando en minusculas).
    std::string baja;
    baja.reserve(linea.size());
    for (char c : linea)
        baja.push_back((char)std::tolower((unsigned char)c));
    const size_t p = baja.find(mnem);
    if (p == std::string::npos) return out;
    size_t i = p + mnem.size();

    std::string cur;
    int prof = 0; // profundidad de corchetes
    auto cerrar = [&] {
        /* Se recorta tambien el RETORNO DE CARRO: un fuente de Windows lleva
         * `\r\n`, asi que al partir por `\n` el ultimo operando de cada linea
         * se llamaba `v0\r` -- que no canonicaliza a ningun registro, y se
         * perdia en silencio lo que ese operando dijera. */
        static const char *kBlancos = " \t\r";
        size_t a = cur.find_first_not_of(kBlancos);
        size_t b = cur.find_last_not_of(kBlancos);
        if (a != std::string::npos) out.push_back(cur.substr(a, b - a + 1));
        cur.clear();
    };
    for (; i < linea.size(); ++i) {
        const char c = linea[i];
        if (c == '[') ++prof;
        if (c == ']' && prof > 0) --prof;
        if (c == ',' && prof == 0) {
            cerrar();
            continue;
        }
        cur.push_back(c);
    }
    cerrar();
    return out;
}

/// Registro base de un operando de memoria.  La operacion vive en el modulo de
/// efectos (@ref asm_base_de_memoria) porque la preguntan DOS: quien quiere
/// saber que memoria toca el bloque y quien quiere saber si se cumple lo que la
/// instruccion EXIGE.  Aqui solo se le pone el nombre corto que usa el fichero.
inline std::string base_de_memoria(const std::string &operando,
                                   const std::string &arch) {
    return asm_base_de_memoria(operando, arch);
}

/// @c true si @p mnem es una rama/salto (para @c has_branch).  Cubre x86
/// (jmp/jCC/loop) y arm64 (b/b.CC/cbz/cbnz/tbz/tbnz).
bool es_rama(const std::string &mnem) {
    if (mnem.empty()) return false;
    if (mnem == "jmp" || mnem == "loop" || mnem == "loope" || mnem == "loopne")
        return true;
    if (mnem[0] == 'j' && mnem.size() >= 2) return true; // jCC (je/jne/jg/...)
    // arm64: b, b.CC, bl, br, cbz, cbnz, tbz, tbnz.
    if (mnem == "b" || mnem == "bl" || mnem == "br" || mnem == "cbz" ||
        mnem == "cbnz" || mnem == "tbz" || mnem == "tbnz")
        return true;
    if (mnem.size() > 2 && mnem[0] == 'b' && mnem[1] == '.')
        return true; // b.ne / b.eq / ...
    return false;
}

/// @c true si @p mnem es una atomica de arm64 (LL/SC o CAS/RMW/swap): base para
/// @c has_atomic.  Se reconoce por prefijo para cubrir todas las variantes de
/// orden/ancho (ldaxr/ldaxrb/..., cas/casa/casal/..., ldadd*/ldset*/swp*).
bool es_atomica_arm(const std::string &mnem) {
    static const char *pref[] = {
        "ldaxr", "ldxr", "ldar", "stlxr", "stxr",  "stlr",  "ldaxp", "ldxp",
        "stlxp", "stxp", "cas",  "swp",   "ldadd", "ldset", "ldclr", "ldeor"};
    for (const char *p : pref)
        if (mnem.rfind(p, 0) == 0) return true;
    return false;
}

/// Ancho (bytes) del slot de pila de un @c push/@c pop segun el arch x86.
int stack_word_x86(const std::string &arch) {
    if (arch == "x86_16") return 2;
    if (arch == "x86") return 4; // x86-32
    return 8;                    // x86_64
}

/// Delta de pila EXPLICITO de una instruccion, en bytes (positivo = mas marco).
/// x86: @c push/@c pop (ancho por arch) y @c sub/@c add sobre @c rsp/@c esp/
/// @c sp; arm64: @c sub/@c add sobre @c sp.  Pone @p ok=false si mueve el
/// puntero de pila con un inmediato NO literal (conservador: no acotable).
int64_t stack_delta(const std::vector<std::string> &toks, size_t mi,
                    const std::string &arch, bool &ok) {
    ok = true;
    const std::string m = lower(toks[mi]);
    const bool x86 = (arch.rfind("x86", 0) == 0 || arch.empty());
    if (x86) {
        const int w = stack_word_x86(arch);
        if (m == "push") return w;
        if (m == "pop") return -w;
    }
    // sub/add <sp>, <imm> (x86: rsp/esp/sp; arm64: `sub sp, sp, #imm`).
    if ((m == "sub" || m == "add") && mi + 2 < toks.size()) {
        const std::string dst = lower(toks[mi + 1]);
        const bool is_sp = (dst == "rsp" || dst == "esp" || dst == "sp");
        if (is_sp) {
            // arm64: `sub sp, sp, #imm` -> el inmediato es el 3er operando y
            // lleva '#'.  x86: `sub rsp, imm` -> 2o operando.
            std::string imm =
                (!x86 && mi + 3 < toks.size()) ? toks[mi + 3] : toks[mi + 2];
            if (!imm.empty() && imm[0] == '#') imm = imm.substr(1);
            char *end = nullptr;
            /* Ancho FIJO, no `long`.  En Windows un `long` mide 32 bits y
             * `strtol` recorta a 2147483647 SIN DECIRLO, asi que un `sub rsp,
             * <inmediato grande>` daba un tamano de marco equivocado en vez de
             * un error.  Mismo fallo que tenia el umbral del JIT: ver la nota
             * en `src/jit/auto_jit.cpp`. */
            const int64_t v =
                static_cast<int64_t>(std::strtoll(imm.c_str(), &end, 0));
            if (end != imm.c_str() && *end == '\0') {
                const int64_t d = v;
                return (m == "sub") ? d : -d;
            }
            ok = false; // sp movido con algo no literal.
            return 0;
        }
    }
    return 0;
}

} // namespace

AsmBlockEffects asm_analyze_block_no_classes(const std::string &nasm_body,
                                             const std::string &arch) {
    return asm_analyze_block(nasm_body, arch, {});
}

AsmBlockEffects asm_analyze_block(
    const std::string &nasm_body, const std::string &arch,
    const std::vector<std::pair<std::string, std::string>> &clases_operando) {
    AsmBlockEffects res;
    // Marco de pila: seguimos el maximo alcanzado (peor caso), no el neto: un
    // `sub rsp,32; ...; add rsp,32` reserva 32 aunque acabe en 0.
    std::set<std::string> escritos; // registros que el bloque reescribe
    int64_t cur_frame = 0;
    int64_t max_frame = 0;

    /* De donde sale lo que hay en cada registro, MIENTRAS se recorre el bloque.
     *
     * Un acceso por `[rdi]` no dice a donde va si el bloque toco `rdi` antes;
     * pero tocarlo no es perderlo: `add rdi, 8` lo deja a ocho bytes de donde
     * estaba, y eso se sabe.  Aqui se sigue cada registro como "de donde
     * partio, y a que distancia esta ahora".
     *
     * Un registro empieza siendo el suyo a distancia cero.  Deja de seguirse en
     * cuanto le entra algo que no se sabe -- una carga de memoria, el resultado
     * de una multiplicacion, otro registro no seguible --, y entonces un acceso
     * a traves de el no se atribuye a nadie.
     */
    struct Origen {
        std::string base; ///< de que registro partio (canonico o `$N`).
        int64_t distancia = 0;
        /// El valor se CARGO de `[base + distancia]` en vez de calcularse a
        /// partir de el.  No es perderlo: es una indireccion mas, y quien tenga
        /// el programa alrededor puede seguirla.
        bool indirecto = false;
        bool seguible = true;
    };
    std::unordered_map<std::string, Origen> origen;
    // El estado de @p reg ahora mismo; si no se ha tocado, es el suyo propio.
    auto origen_de = [&](const std::string &reg) -> Origen {
        auto it = origen.find(reg);
        if (it != origen.end()) return it->second;
        return Origen{reg, 0, false, true};
    };
    /* Un bloque con RAMAS no se puede recorrer asi: por cada camino el registro
     * llega con una distancia distinta, y quedarse con la del texto es contar
     * un camino que quiza no se toma.  Con ramas se sigue diciendo POR DONDE se
     * accede, pero no a que distancia. */
    bool seguimiento_valido = true;

    size_t i = 0;
    const std::string &b = nasm_body;
    while (i <= b.size()) {
        size_t eol = b.find('\n', i);
        if (eol == std::string::npos) eol = b.size();
        std::string line = b.substr(i, eol - i);
        i = eol + 1;

        // Comentarios ';' y '//'.
        size_t cpos = line.find(';');
        if (cpos != std::string::npos) line = line.substr(0, cpos);
        size_t slpos = line.find("//");
        if (slpos != std::string::npos) line = line.substr(0, slpos);

        /* Un acceso a memoria se escribe distinto en cada arquitectura --
         * `[base]` en x86 y ARM, `desplazamiento(base)` en RISC-V --, asi que
         * se pregunta por la sintaxis en vez de buscar el corchete de una
         * dentro del texto de otra: buscarlo dejaba a RISC-V sin ningun acceso
         * reconocido, ni sus cargas ni sus almacenes. */
        const bool line_has_mem = vx::asm_is_memory(line, arch);

        auto toks = tokenize_line(line);
        if (toks.empty()) continue;

        // Saltar labels ("name:") y prefijos; detectar el prefijo `lock`
        // (barrera atomica) por el camino.
        size_t ti = 0;
        bool lock_prefix = false;
        /* Prefijo de REPETICION.  Cambia lo que se puede decir del acceso: la
         * instruccion no toca lo que miden sus operandos, lo toca tantas veces
         * como diga `rcx` -- un valor de EJECUCION.  Sin distinguirlo, un
         * `rep movsq` diria que mueve ocho bytes, que es exactamente la clase
         * de afirmacion que hace mas dano que no decir nada. */
        bool rep_prefix = false;
        while (ti < toks.size()) {
            const std::string &t = toks[ti];
            if (!t.empty() && t.back() == ':') { // label
                ++ti;
                continue;
            }
            const std::string lt = lower(t);
            if (lt == "lock") {
                lock_prefix = true;
                ++ti;
                continue;
            }
            if (lt == "rep" || lt == "repe" || lt == "repz" || lt == "repne" ||
                lt == "repnz") {
                rep_prefix = true;
                ++ti;
                continue;
            }
            if (lt == "bnd") {
                ++ti;
                continue;
            }
            break;
        }
        if (ti >= toks.size()) continue; // linea solo-label/prefijo

        const std::string mnem = lower(toks[ti]);

        if (lock_prefix || line_has_mem) res.touches_mem = true;
        // Prefijo `lock` (x86) o una atomica de arm64 (LL/SC o CAS/RMW/swap) =
        // efecto atomico (barrera).
        if (lock_prefix || es_atomica_arm(mnem)) res.has_atomic = true;
        if (es_rama(mnem)) {
            res.has_branch = true;
            // Ver la nota de @c seguimiento_valido: con dos caminos, la
            // distancia que diga el texto es la de uno solo.
            seguimiento_valido = false;
        }

        // Marco de pila explicito.
        bool sd_ok = true;
        const int64_t d = stack_delta(toks, ti, arch, sd_ok);
        if (!sd_ok) {
            // El puntero de pila se movio con algo no literal: no acotable.
            res.unknown_mnemonics.push_back(mnem + " sp,<no-literal>");
        } else if (d != 0) {
            cur_frame += d;
            if (cur_frame > max_frame) max_frame = cur_frame;
        }

        // Efectos por-instruccion segun la tabla del arch.  Un mnemonico no
        // tabulado -> a la lista de desconocidos para que el caller de un error
        // claro (disciplina "crecer bajo demanda, error claro siempre").
        /* Nombres que la ISA usa para DOS instrucciones distintas.
         *
         * `movsd` es a la vez "mover una cadena de doble palabra" -- sin
         * operandos, gobernada por los registros de indice -- y "mover un
         * flotante de doble precision" -- con dos operandos --.  Lo mismo
         * `cmpsd`.  El nombre no las distingue; el numero de operandos si.
         *
         * La tabla de efectos solo recibe el mnemonico, asi que no puede
         * desambiguar: por eso la forma flotante vive con el sufijo `_sse`, que
         * no es lo que nadie escribe.  Aqui SI se conocen los operandos, y este
         * es el unico sitio donde se puede resolver.
         *
         * Sin esto, un `movsd [$0], $1` -- guardar un flotante -- se tomaba por
         * la de cadena: los efectos que se le atribuian eran los de otra
         * instruccion. */
        const std::vector<std::string> ops_de_linea = operandos_de(line, mnem);
        std::string mnem_efectos = mnem;
        if (!ops_de_linea.empty() && (mnem == "movsd" || mnem == "cmpsd"))
            mnem_efectos = mnem + "_sse";
        /* Y `imul` es el mismo caso por otra via: con UN operando multiplica
         * contra el acumulador y deja el resultado en `rdx:rax`; con dos o
         * tres, solo en su destino y sin tocar `rdx`.  Estaba tabulado con la
         * forma de un operando "por si acaso", asi que un `imul rax, rbx` --
         * que es la forma que escribe cualquiera -- salia destruyendo `rdx`.
         * Eso no es conservador: es afirmar un efecto que no existe, y con el
         * se pierde el valor que hubiera ahi. */
        else if (ops_de_linea.size() >= 2 && mnem == "imul")
            mnem_efectos = "imul_2op";
        AsmEffects eff = asm_effects_for(mnem_efectos, arch);

        /* Lo que la tabla escrita a mano no conoce, lo sabe la BASE DE DATOS.
         *
         * De las 1930 instrucciones que la base describe, la tabla cubria 318.
         * Las otras 1612 caian en "no se sabe", y eso cuesta una de dos cosas:
         * si se resuelve conservador, el bloque es una barrera y alrededor no
         * se mueve nada; si se resuelve permisivo, deja pasar optimizaciones
         * que rompen -- lo que paso con `movdqa` y con la aritmetica
         * empaquetada.
         *
         * Pero la base YA tiene la respuesta: por forma sabe si lee o escribe
         * memoria, si toca banderas, si es una barrera y que registros lee y
         * escribe implicitamente.  La tabla a mano estaba duplicando ese
         * conocimiento para una fraccion de las instrucciones y dejando el
         * resto sin nada.
         *
         * Asi que la tabla pasa a ser lo que debe: las EXCEPCIONES -- lo que la
         * base no puede expresar, como la exigencia de alineacion de las formas
         * alineadas -- y todo lo demas se deriva.  Se consulta con la LiNEA, no
         * con el mnemonico, porque la base responde por forma y es la linea la
         * que dice cual: `movsd` con operandos y sin ellos son dos
         * instrucciones.
         *
         * `modeled == false` significa que la base no pudo emparejar la forma o
         * que la instruccion tiene operandos implicitos; ahi NO se deriva,
         * porque afirmar sobre una forma que no se reconocio es peor que no
         * afirmar. */
        if (!eff.known) {
            const vx::instr_db::AsmInsnSem sem = vx::instr_db::asm_insn_sem(
                isa_of_arch(arch), line, /*ua_id=*/0);
            if (sem.modeled) {
                eff.known = true;
                eff.touches_mem = sem.reads_mem || sem.writes_mem;
                eff.writes_flags = sem.writes_flags;
                eff.reads_flags = sem.reads_flags;
                /* QUE clase de instruccion es -- rama, llamada, barrera -- lo
                 * dice la forma, no su nombre.
                 *
                 * Se estaba decidiendo por el nombre, y un nombre solo se
                 * reconoce en la arquitectura para la que se escribio la lista:
                 * `call` y `syscall` de x86, `bl` y `b.eq` de arm64.  Un `bl`
                 * de A32 o un `ecall` de RISC-V no salian como llamada, y un
                 * `beq` de RISC-V no salia como rama -- con lo que el
                 * seguimiento de punteros seguia dando por buena la distancia
                 * de un solo camino habiendo dos.
                 *
                 * La base marca cada forma con lo que es, y eso vale para las
                 * cuatro arquitecturas sin una lista de nombres por cada una.
                 */
                const uint16_t ovl =
                    vx::instr_db::overlay_of(isa_of_arch(arch), sem.form_id);
                if ((ovl & (vx::instr_db::OVL_CALL |
                            vx::instr_db::OVL_SYSCALL)) != 0u)
                    eff.is_call = true;
                if ((ovl & vx::instr_db::OVL_BRANCH) != 0u) {
                    res.has_branch = true;
                    // Con dos caminos, la distancia que diga el texto es la de
                    // uno.
                    seguimiento_valido = false;
                }
                /* Y ORDENAR es otra cosa: una rama no es una barrera de
                 * memoria. La base junta las dos bajo un mismo `barrier`, asi
                 * que aqui se mira el motivo concreto -- barrera, serializante,
                 * atomica, o adquisicion/liberacion -- y no el resumen, que
                 * dejaba cualquier salto pareciendo una valla para la memoria.
                 */
                const uint16_t kOrdena =
                    vx::instr_db::OVL_BARRIER | vx::instr_db::OVL_SERIALIZING |
                    vx::instr_db::OVL_ATOMIC | vx::instr_db::OVL_LL_SC |
                    vx::instr_db::OVL_MEM_ACQUIRE |
                    vx::instr_db::OVL_MEM_RELEASE |
                    vx::instr_db::OVL_MEM_SEQ_CST |
                    vx::instr_db::OVL_NO_REORDER;
                eff.barrier = (ovl & kOrdena) != 0u;
                for (const std::string &r : sem.reads)
                    eff.implicit_read.push_back(r);
                for (const std::string &w : sem.writes)
                    eff.implicit_write.push_back(w);
                /* Y el ESTADO del procesador, con su nombre: es lo que hace que
                 * una instruccion privilegiada quede modelada en vez de opaca.
                 */
                for (const std::string &r : sem.reads_state)
                    eff.implicit_state_read.push_back(r);
                for (const std::string &w : sem.writes_state)
                    eff.implicit_state_write.push_back(w);
                /* El rol de cada operando EXPLICITO tambien lo dice la base, y
                 * es lo que distingue el destino de las fuentes. */
                for (size_t k = 0; k < 8; ++k) {
                    bool lee_op = false, escribe_op = false;
                    if (!vx::instr_db::explicit_operand(isa_of_arch(arch),
                                                        sem.form_id, k, lee_op,
                                                        escribe_op))
                        break;
                    if (escribe_op)
                        eff.operand_write_mask |= (uint8_t)(1u << k);
                }
            }
        }
        if (!eff.known) {
            res.unknown_mnemonics.push_back(mnem);
            continue;
        }
        if (eff.touches_mem) res.touches_mem = true;
        /* Los dos sentidos por separado, y el agregado como la union de ambos:
         * quien solo pregunta "toca las banderas" sigue teniendo respuesta, y
         * quien necesita saber si el bloque DEPENDE de ellas o las DESTRUYE ya
         * no tiene que suponer lo peor de los dos. */
        if (eff.reads_flags) res.reads_flags = true;
        if (eff.writes_flags) res.writes_flags = true;
        if (eff.reads_flags || eff.writes_flags) res.touches_flags = true;
        /* Y CUALES.  Se pregunta a la BASE aunque el mnemonico este en la tabla
         * escrita a mano, porque la tabla solo tiene el bit grueso: dejar que
         * tape al dato mas fino seria quedarse con la peor de las dos
         * respuestas.
         *
         * Un bloque que hace `inc` no toca el acarreo y uno que hace `add` si,
         * y con "toca banderas" a secas los dos obligan a lo mismo a todo lo
         * que los rodea. */
        {
            const vx::instr_db::Isa isa_db = isa_of_arch(arch);
            /* Solo si la forma casó POR OPERANDOS.  Cuando ninguna casa, el
             * emparejador devuelve la primera del rango -- que sirve para saber
             * que existe el mnemonico, no para afirmar sus efectos --, y con
             * eso un `movsd [rdi], xmm0` cogia las banderas de la `movsd` de
             * CADENA, que lee la bandera de direccion.  Las banderas habrian
             * salido de otra instruccion.  `modeled` es justo esa condicion. */
            /* Y con la linea SIN el prefijo.  La base nombra las formas
             * fusionadas (`REP_MOVSB`), asi que preguntarle por `rep movsb` la
             * hace leer `rep` como mnemonico y no encontrar nada: el detalle se
             * perdia justo en las de cadena, que son las que LEEN la bandera de
             * direccion.  El prefijo no cambia que banderas toca la
             * instruccion -- cambia cuantas veces la ejecuta --, asi que se
             * pregunta por ella y ya esta. */
            std::string linea_sin_prefijo = mnem;
            {
                const std::vector<std::string> ops_db =
                    operandos_de(line, mnem);
                for (size_t k = 0; k < ops_db.size(); ++k)
                    linea_sin_prefijo += (k == 0 ? " " : ", ") + ops_db[k];
            }
            const vx::instr_db::AsmInsnSem sem =
                vx::instr_db::asm_insn_sem(isa_db, linea_sin_prefijo,
                                           /*ua_id=*/0);
            const int32_t fid = sem.modeled ? sem.form_id : -1;
            std::vector<std::string> lee, escribe;
            /* Si la forma no caso -- un `adds x0, x1, x2` tiene tres operandos
             * y la forma con desplazamiento tiene cuatro --, se pregunta por el
             * MNEMONICO, que contesta solo si todas sus formas coinciden.  Las
             * banderas de `adds` son las mismas en las cuatro. */
            const bool por_forma = fid >= 0 && vx::instr_db::flag_names_of(
                                                   isa_db, fid, lee, escribe);
            /* Y NO se pregunta por el mnemonico cuando hubo que desambiguarlo:
             * ahi el nombre designa dos instrucciones distintas -- `movsd` es
             * la de cadena y la de SSE --, asi que contestar por el nombre es
             * contestar por la otra.  Es justo el fallo que ya aparecio una
             * vez: un `movsd [rdi], xmm0` cogia la bandera de direccion. */
            const bool nombre_ambiguo = mnem_efectos != mnem;
            if (por_forma ||
                (!nombre_ambiguo && vx::instr_db::flag_names_of_mnemonic(
                                        isa_db, mnem, lee, escribe))) {
                auto anota = [](std::vector<std::string> &dst,
                                const std::vector<std::string> &src) {
                    for (const std::string &n : src) {
                        bool ya = false;
                        for (const std::string &v : dst)
                            if (v == n) {
                                ya = true;
                                break;
                            }
                        if (!ya) dst.push_back(n);
                    }
                };
                /* En A32 casi toda instruccion admite condicion, asi que la
                 * base modela la clase entera como que LEE las banderas.  Pero
                 * la condicion va pegada al mnemonico (`addeq`), y un `add` a
                 * secas es incondicional: no depende de nada.  Quien lo sabe es
                 * la tabla, que separa el sufijo, asi que ahi manda ella -- si
                 * dice que no lee, no se le atribuye la lectura de la clase. */
                /* En ARM la condicion va en el MNEMONICO (`addeq`, `b.eq`), y
                 * la base modela la clase entera -- rama condicional e
                 * incondicional comparten iclass y forma explicita --.  Quien
                 * las separa es la tabla, que lee el sufijo: si dice que no
                 * lee, no se le atribuye la lectura de la clase.  Sin esto, un
                 * `b` a secas salia leyendo las cuatro banderas de su hermana
                 * condicional. */
                const bool a32 = arch == "arm32" || arch == "arm" ||
                                 arch == "arm64" || arch == "aarch64";
                if (!a32 || eff.reads_flags) anota(res.flags_read, lee);
                anota(res.flags_written, escribe);
                /* Si la base dice que toca alguna, el agregado tambien lo dice:
                 * los dos caminos tienen que contar lo mismo. */
                if (!lee.empty() && (!a32 || eff.reads_flags)) {
                    res.reads_flags = true;
                    res.touches_flags = true;
                }
                if (!escribe.empty()) {
                    res.writes_flags = true;
                    res.touches_flags = true;
                }
            }
        }
        if (eff.is_call) res.is_call = true;
        if (eff.port_io) res.has_port_io = true;
        if (eff.barrier) res.has_atomic = true; // ordena: misma consecuencia

        /* Leer y escribir memoria no es lo mismo, y la tabla ya sabe cual de
         * las dos: @c operand_write_mask dice QUE operandos escribe la
         * instruccion, asi que basta con mirar en que posicion esta el de
         * memoria.  Se apunta lo justo, y ante cualquier duda las dos cosas --
         * decir de menos aqui seria dejar reordenar algo que no se puede. */
        if (lock_prefix || line_has_mem || eff.touches_mem) {
            bool lee = true, escribe = true; // por defecto, lo conservador
            if (line_has_mem) {
                /* Memoria EXPLICITA (`[...]` en un operando): se puede precisar
                 * si se identifica cual es.
                 *
                 * El prefijo `lock` NO lo impide, y excluirlo era un error: da
                 * atomicidad y ordena, pero no cambia QUE memoria se toca -- un
                 * `lock inc [rdi]` toca exactamente `[rdi]`, con los corchetes
                 * a la vista --.  Se quedaba fuera de la atribucion, o sea que
                 * un bloque atomico salia tocando memoria que no sabe nombrar y
                 * con ello se suponia lo peor de toda.  Lo que el prefijo si
                 * obliga es a contar los DOS sentidos, y eso se aplica mas
                 * abajo.
                 *
                 * La condicion es tener CORCHETES, no que la instruccion toque
                 * memoria "implicitamente": en arm64 toda carga o almacen la
                 * toca por definicion y aun asi lleva su `[x0]` a la vista.
                 * Exigir lo segundo dejaba fuera a arm64 entero.  Lo que si
                 * queda fuera es la memoria SIN corchetes -- `push`, `call`,
                 * las de cadena --, que no se puede atribuir a nada. */
                const std::vector<std::string> ops = operandos_de(line, mnem);
                int idx_mem = -1;
                bool varios = false;
                for (size_t k = 0; k < ops.size(); ++k)
                    if (vx::asm_is_memory(ops[k], arch)) {
                        if (idx_mem >= 0)
                            varios = true;
                        else
                            idx_mem = static_cast<int>(k);
                    }
                /* Corchetes que NO son un acceso: hay instrucciones cuyo
                 * operando entre corchetes es una direccion que se CALCULA, no
                 * una que se sigue.  `lea rax, [rbx+8]` no lee memoria: hace
                 * aritmetica.
                 *
                 * No es una excepcion de x86 -- `adr`/`adrp` de arm64 hacen lo
                 * mismo -- y no se decide aqui por el nombre: se pregunta por
                 * su CLASE, que el modulo de efectos ya sabe responder
                 * (@c AsmTransferencia::Direccion).
                 *
                 * Contarlo como lectura no daba un resultado falso, daba algo
                 * mas sutil: el bloque pasaba a parecer que toca memoria, y con
                 * eso se convierte en una barrera para todo lo que le rodea --
                 * no se puede mover una escritura, ni subir una lectura fuera
                 * de un bucle, ni eliminar una escritura muerta.  Y `lea` esta
                 * por todas partes. */
                const bool solo_calcula_direccion =
                    vx::asm_transferencia(mnem, arch) ==
                    AsmTransferencia::Direccion;
                if (solo_calcula_direccion) {
                    idx_mem = -1;
                    /* Y no lee ni escribe.  `lee` arranca en `true` -- lo
                     * conservador cuando no se sabe --, asi que quitar el
                     * acceso no basta: sin esto la instruccion seguia
                     * declarando una lectura por el valor de partida, que es
                     * justo el efecto que la convierte en barrera. */
                    lee = false;
                    escribe = false;
                }
                if (solo_calcula_direccion) {
                    /* No hay acceso que atribuir, y eso NO es lo mismo que un
                     * acceso que no se ha podido atribuir: lo segundo obliga a
                     * suponer lo peor de toda la memoria.  Sin distinguirlos,
                     * el `lea` volvia a ser una barrera por la otra puerta --
                     * ya no declaraba la lectura, pero dejaba el bloque marcado
                     * como que toca memoria que no sabe nombrar. */
                } else if (idx_mem >= 0 && !varios && idx_mem < 8) {
                    escribe = ((eff.operand_write_mask >> idx_mem) & 1u) != 0u;
                    lee = !escribe || (eff.operand_write_mask == 0u);
                    /* Un operando que se escribe puede ademas leerse (`add
                     * [rdi], rax` acumula).  Solo un destino PURO -- el `mov`
                     * -- no lee lo que pisa, y distinguirlo no compensa el
                     * riesgo: si escribe, se cuenta tambien como lectura. */
                    if (escribe) lee = true;
                    /* Y una operacion ATOMICA lee y escribe siempre: eso es lo
                     * que la hace atomica.  El prefijo no cambia por donde --
                     * eso ya se atribuyo arriba --, cambia que los dos sentidos
                     * estan garantizados. */
                    if (lock_prefix) {
                        lee = true;
                        escribe = true;
                    }
                    /* Por donde se llega y hasta donde llega.  Si no se sabe lo
                     * primero, el bloque toca memoria que no se puede nombrar y
                     * hay que decirlo; lo segundo puede faltar sin que lo
                     * primero se pierda. */
                    const AsmMemOperando mem = asm_parse_memoria(
                        ops[static_cast<size_t>(idx_mem)], arch);
                    if (mem.base.empty()) {
                        res.accesos_incompletos = true;
                    } else {
                        AsmBlockEffects::Acceso ac;
                        /* El registro puede no valer ya lo que valia al entrar
                         * -- `mov rdi, rsi`, `add rdi, 8`, `mov rdi, [rsi+8]`
                         * --, y eso NO es perderlo: se sabe de donde partio, a
                         * que distancia esta, y si hubo que ir a buscarlo a
                         * memoria.  Se atribuye a su origen. */
                        const Origen org = origen_de(mem.base);
                        if (!org.seguible) {
                            // Le entro algo de fuera en ejecucion: aqui si se
                            // acaba lo que se puede decir.
                            res.accesos_incompletos = true;
                            continue;
                        }
                        ac.base = org.base;
                        ac.escribe = escribe;
                        if (org.indirecto) {
                            ac.desde_memoria.hay = true;
                            ac.desde_memoria.off = org.distancia;
                        }
                        /* Y hasta donde llega, nombrando de que depende lo que
                         * no sea constante en vez de callarlo. */
                        AsmBlockEffects::Extension ex;
                        ex.bytes = asm_ancho_acceso_bytes(
                            ops, static_cast<size_t>(idx_mem), clases_operando,
                            arch);
                        ex.const_off = mem.desplazamiento +
                                       (org.indirecto ? 0 : org.distancia);
                        ex.indice = mem.indice;
                        ex.escala = mem.escala;
                        /* Un prefijo de repeticion no hace opaco el acceso: lo
                         * repite tantas veces como diga su contador, y ese
                         * contador tiene nombre.  Quien tenga sus ligaduras
                         * sabra entre que valores se mueve. */
                        if (rep_prefix)
                            ex.repeticion = asm_contador_de_repeticion(arch);
                        /* La extension describe algo si la expresion de dentro
                         * de los corchetes se pudo leer entera y se sabe por
                         * que camino se llego -- con ramas, la distancia del
                         * texto es la de UNO de ellos. */
                        ac.valida = mem.reconocido && seguimiento_valido;
                        ac.extension = std::move(ex);
                        res.accesos.push_back(std::move(ac));
                    }
                    /* El registro base tiene que seguir valiendo lo que la
                     * ligadura dice.  Si el propio bloque lo reescribe antes
                     * -- `mov rdi, rsi` y luego `[rdi]` --, el acceso ya no va
                     * a donde apuntaba la variable, y atribuirselo seria
                     * mentir.  Se anota que registros escribe el bloque y al
                     * final se descartan los accesos que dependan de ellos. */
                } else {
                    res.accesos_incompletos = true;
                }
            } else if (!eff.implicit_mem_read.empty() ||
                       !eff.implicit_mem_write.empty()) {
                /* Memoria IMPLICITA pero CONOCIDA: la instruccion no escribe
                 * los corchetes, pero la arquitectura dice por que registro
                 * accede (`movsb` va de `rsi` a `rdi`).  Se apunta igual que un
                 * acceso escrito a mano -- saberlo y no decirlo seria dejar el
                 * analisis a medias. */
                lee = !eff.implicit_mem_read.empty();
                escribe = !eff.implicit_mem_write.empty();
                /* Tambien aqui se dice hasta donde llega: la instruccion
                 * declara cuanto toca cada paso, y el prefijo de repeticion
                 * NOMBRA lo que dice cuantos pasos hay.  Un `rep movsb` recorre
                 * `[dst, dst + rcx)`, y eso es un hecho aunque `rcx` no sea una
                 * constante -- quien tenga sus ligaduras sabra acotarlo. */
                auto implicito = [&](const std::string &reg,
                                     bool escribe_aqui) {
                    AsmBlockEffects::Acceso ac;
                    const Origen org = origen_de(reg);
                    if (!org.seguible) {
                        res.accesos_incompletos = true;
                        return;
                    }
                    ac.base = org.base;
                    ac.escribe = escribe_aqui;
                    if (org.indirecto) {
                        ac.desde_memoria.hay = true;
                        ac.desde_memoria.off = org.distancia;
                    }
                    ac.extension.const_off = org.indirecto ? 0 : org.distancia;
                    ac.extension.bytes = eff.mem_bytes_implicito;
                    if (rep_prefix)
                        ac.extension.repeticion =
                            asm_contador_de_repeticion(arch);
                    ac.valida = seguimiento_valido;
                    res.accesos.push_back(std::move(ac));
                };
                for (const std::string &r : eff.implicit_mem_read)
                    implicito(r, false);
                for (const std::string &w : eff.implicit_mem_write)
                    implicito(w, true);
            } else {
                // Atomica o mnemonico cuya memoria no esta acotada: no se puede
                // atribuir a un registro base.
                res.accesos_incompletos = true;
            }
            if (lee) res.reads_mem = true;
            if (escribe) res.writes_mem = true;
        }

        /* De donde pasa a venir lo que hay en un registro que esta linea
         * escribe.  Es lo que evita rendirse en cuanto el bloque toca su propia
         * base: `add rdi, 8` no borra a `rdi`, lo mueve ocho bytes.
         *
         * Se reconocen las formas que de verdad mueven un puntero -- copiarlo,
         * sumarle o restarle una constante, calcular una direccion, cargarlo de
         * memoria -- y CUALQUIER otra cosa deja el registro sin seguir.  Ese
         * "cualquier otra" es lo unico que se rinde, y se rinde para el
         * registro, no para el bloque entero. */
        {
            const std::vector<std::string> ops = operandos_de(line, mnem);
            const bool escribe_dst =
                !ops.empty() && ((eff.operand_write_mask & 1u) != 0u);
            if (escribe_dst && ops[0].find('[') == std::string::npos) {
                const std::string dst = (!ops[0].empty() && ops[0][0] == '$')
                                            ? ops[0]
                                            : asm_canonical_reg(ops[0], arch);
                if (!dst.empty()) {
                    Origen nuevo;
                    nuevo.seguible = false;
                    /* Se pregunta por la CLASE de transferencia, no por el
                     * mnemonico: cada arquitectura declara los suyos y esto
                     * vale igual para todas.  La forma de los operandos --
                     * si la fuente lleva corchetes -- separa copiar de cargar,
                     * y eso no necesita tabla. */
                    const AsmTransferencia tr = asm_transferencia(mnem, arch);
                    const size_t i_src = (ops.size() >= 3) ? 2 : 1;
                    const std::string src =
                        (ops.size() > i_src) ? ops[i_src] : std::string();
                    const bool src_mem = src.find('[') != std::string::npos;
                    // De donde parte un operando que es un registro.
                    auto origen_fuente_reg =
                        [&](const std::string &t) -> Origen {
                        if (t.empty() || t.find('[') != std::string::npos)
                            return Origen{};
                        const std::string r =
                            (t[0] == '$') ? t : asm_canonical_reg(t, arch);
                        return r.empty() ? Origen{} : origen_de(r);
                    };
                    auto origen_fuente = [&]() -> Origen {
                        return src_mem ? Origen{} : origen_fuente_reg(src);
                    };
                    // Lo que describe una fuente de MEMORIA, si se puede leer.
                    auto origen_memoria = [&](bool leyendo) -> Origen {
                        Origen o;
                        o.seguible = false;
                        if (!src_mem) return o;
                        const AsmMemOperando sm = asm_parse_memoria(src, arch);
                        if (sm.base.empty() || !sm.reconocido ||
                            !sm.indice.empty())
                            return o;
                        const Origen so = origen_de(sm.base);
                        if (!so.seguible || so.indirecto) return o;
                        o.base = so.base;
                        o.distancia = so.distancia + sm.desplazamiento;
                        o.indirecto = leyendo;
                        o.seguible = true;
                        return o;
                    };
                    switch (tr) {
                    case AsmTransferencia::Transfiere:
                        // Copiarlo o traerlo de memoria: la fuente manda.
                        nuevo = src_mem ? origen_memoria(/*leyendo=*/true)
                                        : origen_fuente();
                        break;
                    case AsmTransferencia::Direccion:
                        // La DIRECCION que describe la fuente, sin leerla.
                        nuevo = origen_memoria(/*leyendo=*/false);
                        break;
                    case AsmTransferencia::Suma:
                    case AsmTransferencia::Resta: {
                        /* Sumar o restar una CONSTANTE lo mueve.  El registro
                         * que se desplaza es el destino cuando hay dos
                         * operandos
                         * (`add rdi, 8`) y el segundo cuando hay tres
                         * (`add x0, x1, #8`); el sentido lo dice la clase, no
                         * la letra del mnemonico. */
                        const Origen actual = (ops.size() >= 3)
                                                  ? origen_fuente_reg(ops[1])
                                                  : origen_de(dst);
                        std::string num;
                        for (char c : src)
                            if (!std::isspace((unsigned char)c) && c != '#')
                                num.push_back(c);
                        const bool es_num =
                            !num.empty() &&
                            (std::isdigit((unsigned char)num[0]) ||
                             num[0] == '-' || num[0] == '+');
                        if (es_num && actual.seguible && !actual.indirecto) {
                            const long long v =
                                std::strtoll(num.c_str(), nullptr, 0);
                            nuevo = actual;
                            nuevo.distancia += (tr == AsmTransferencia::Resta)
                                                   ? -(int64_t)v
                                                   : (int64_t)v;
                        }
                        break;
                    }
                    case AsmTransferencia::Ninguna:
                        break; // no propaga: el registro deja de seguirse.
                    }
                    origen[dst] = std::move(nuevo);
                }
            }
        }

        /* Registros que el bloque ESCRIBE: los que la tabla marca como
         * implicitos y los operandos que su mascara senala.  Se acumulan para
         * invalidar despues los accesos cuya base pise el propio bloque. */
        for (const std::string &w : eff.implicit_write)
            escritos.insert(w);
        /* Y el ESTADO del procesador que toca la linea, con su nombre.  Se
         * acumula sin repetir: un bloque que hace tres `wrmsr` escribe `msrs`,
         * no lo escribe tres veces. */
        auto anota_estado = [](std::vector<std::string> &dst,
                               const std::vector<std::string> &src) {
            for (const std::string &e : src) {
                bool ya = false;
                for (const std::string &v : dst)
                    if (v == e) {
                        ya = true;
                        break;
                    }
                if (!ya) dst.push_back(e);
            }
        };
        anota_estado(res.state_read, eff.implicit_state_read);
        anota_estado(res.state_written, eff.implicit_state_write);
        {
            const std::vector<std::string> ops = operandos_de(line, mnem);
            for (size_t k = 0; k < ops.size() && k < 8; ++k) {
                if (((eff.operand_write_mask >> k) & 1u) == 0u) continue;
                if (ops[k].find('[') != std::string::npos) continue;
                // Un marcador se anota tal cual: `mov $0, $1` pisa la base $0
                // igual que `mov rdi, rsi` pisa rdi.
                if (!ops[k].empty() && ops[k][0] == '$') {
                    escritos.insert(ops[k]);
                    continue;
                }
                const std::string c = asm_canonical_reg(ops[k], arch);
                if (!c.empty()) escritos.insert(c);
            }
        }
    }

    /* Aqui habia una poda: si el bloque reescribia el registro base de un
     * acceso, se descartaba la lista ENTERA.  Ya no hace falta y ademas seria
     * falsa, por dos motivos: cada acceso se atribuye al origen que su registro
     * tenia EN SU PUNTO -- un `mov [rdi], rax` seguido de `add rdi, 8` es un
     * acceso perfectamente descrito --, y un registro al que le entra algo que
     * no se puede seguir ya se marca incompleto donde se usa, sin arrastrar a
     * los demas. */
    res.escritos.assign(escritos.begin(), escritos.end());

    res.explicit_stack_bytes = max_frame;
    return res;
}

} // namespace vx
