/**
 * @file instr_db.cpp
 * @brief Emparejador texto->FormID sobre la DB de instrucciones EMBEBIDA.
 *
 * Las tablas por-ISA las genera @c tools/import/gen_cpp_db.py (ficheros
 * @c gen/instr_db_<isa>_gen.inc, incluidos aqui como @c .rodata estatica).  El
 * @c match espeja el emparejador del analizador: rango del iclass por busqueda
 * binaria + puntuacion por clase/ancho de operando.
 */
#include "vx/asm/instr_db.h"

#include "vx/asm/asm_effects.h" // asm_canonical_reg (colapsa alias de registro)

#include <algorithm>
#include <cctype>
#include <cstring>
#include <initializer_list>

namespace vx {
namespace instr_db {

namespace {

/// Tablas de una ISA (las rellena el accesor @c db_<isa>() del .cpp generado).
IsaData tables_for(Isa isa) {
    switch (isa) {
    case Isa::X86: return db_x86();
    case Isa::ARM64: return db_arm64();
    case Isa::ARM32: return db_arm32();
    case Isa::RISCV: return db_riscv();
    }
    return {};
}

/// Operandos EXPLICITOS de una forma para puntuar (descarta implicit/suppressed
/// y los operandos de flags, que el usuario no escribe).
void explicit_ops(const IsaData &t, const DbForm &f,
                  std::vector<const DbOperand *> &out) {
    out.clear();
    for (unsigned i = 0; i < f.ops_count; ++i) {
        const DbOperand &o = t.ops[f.ops_off + i];
        if (o.flags & 0x0C) continue; // implicit(bit2) | suppressed(bit3)
        if (!op_kind_is_textual(o.kind)) continue;
        out.push_back(&o);
    }
}

/// Puntua los operandos del usuario contra los de la forma; -1 si no casan.
int score_ops(const std::vector<ParsedOp> &user,
              const std::vector<const DbOperand *> &form) {
    /* Se pueden OMITIR los operandos opcionales del final.
     *
     * `ADDS <Wd>, <Wn>, <Wm>{, <shift> #<amount>}` declara cinco operandos y un
     * `adds w0, w1, w2` escribe tres: exigir la misma cuenta hacia que la forma
     * no casara NUNCA, y el emparejador se quedaba a nivel de mnemonico -- de
     * ahi el rodeo de responder por el nombre --.  Los que sobran tienen que
     * ser
     * TODOS opcionales (bit4); si alguno no lo es, faltan operandos de verdad.
     *
     * Casar exacto puntua mas: entre una forma que usa todos sus operandos y
     * otra que deja opcionales fuera, gana la que encaja del todo. */
    if (user.size() > form.size()) return -1;
    int s = 0;
    if (user.size() < form.size()) {
        for (size_t i = user.size(); i < form.size(); ++i)
            if ((form[i]->flags & 0x10) == 0) return -1; // no era opcional
        s -= 1; // encajo, pero dejando cosas fuera
    }
    for (size_t i = 0; i < user.size(); ++i) {
        const ParsedOp &u = user[i];
        const DbOperand &fo = *form[i];
        if (u.kind != fo.kind) return -1;
        if (u.width && fo.width) {
            if (u.width != fo.width) return -1;
            s += 2;
        } else {
            s += 1;
        }
    }
    return s;
}

/// Busca el rango de FormIDs de un mnemonico (binaria sobre kIclassIndex,
/// ordenado por nombre).  Devuelve nullptr si no existe.
const DbIclassRange *find_iclass(const IsaData &t, const std::string &up) {
    unsigned lo = 0, hi = t.iclass_count;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        const DbIclassRange &r = t.iclass[mid];
        int c = std::strcmp(t.str[r.iclass], up.c_str());
        if (c == 0) return &r;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return nullptr;
}

/// Nombre CANONICO de una condicion x86, o nullptr si la escrita ya lo es.
///
/// El ensamblador acepta varios nombres para la misma condicion -- `jne` y
/// `jnz` son la MISMA instruccion, igual que `jc` y `jb`, o `setg` y `setnle`
/// --, y la base guarda uno solo por condicion: el que nombra la fuente.  Sin
/// esta equivalencia, la mitad de los saltos que se escriben de verdad no
/// existian para la base.
const char *cond_canonica_x86(const std::string &c) {
    static const std::pair<const char *, const char *> alias[] = {
        {"A", "NBE"}, {"AE", "NB"}, {"C", "B"},   {"E", "Z"},   {"G", "NLE"},
        {"GE", "NL"}, {"NA", "BE"}, {"NAE", "B"}, {"NC", "NB"}, {"NE", "NZ"},
        {"NG", "LE"}, {"NGE", "L"}, {"PE", "P"},  {"PO", "NP"},
    };
    for (const auto &a : alias)
        if (c == a.first) return a.second;
    return nullptr;
}

/// Busca la clase de un mnemonico TAL Y COMO SE ESCRIBE.
///
/// @ref find_iclass busca el nombre exacto de la base, que es el de la fuente
/// de la que salio (estilo XED en x86).  Ese nombre y el que se teclea no
/// siempre coinciden, y no por capricho: la base separa lo que el ensamblador
/// deja junto -- `ret` son dos instrucciones distintas segun a donde vuelva,
/// `RET_NEAR` y `RET_FAR` --, y elige un nombre por condicion donde el
/// ensamblador admite varios.  Preguntar solo por el nombre exacto dejaba
/// mudos precisamente a los mnemonicos mas comunes: `ret`, `call`, `jne`,
/// `ja`, `sete`, `cmovg`.
///
/// Aqui se resuelve una vez, para que lo ganen a la vez el planificador, el
/// analisis, el informe y el editor.
///
/// @param t   Tablas de la ISA.
/// @param isa ISA a la que pertenece el mnemonico.
/// @param up  Mnemonico ya en mayusculas.
/// @return El rango de formas, o nullptr si la base no lo conoce.
const DbIclassRange *find_iclass_escrito(const IsaData &t, Isa isa,
                                         const std::string &up) {
    if (const DbIclassRange *r = find_iclass(t, up)) return r;

    /* En arm la condicion va PEGADA al mnemonico (`b.ne`) y la base nombra la
     * clase sin ella (`B`): la condicion es un campo del encoding, no otra
     * instruccion. */
    if (isa == Isa::ARM64 || isa == Isa::ARM32) {
        const size_t punto = up.find('.');
        if (punto != std::string::npos && punto > 0)
            return find_iclass(t, up.substr(0, punto));
        return nullptr;
    }
    if (isa != Isa::X86) return nullptr;

    /* Los nombres que el ensamblador deja sin desambiguar.  `ret` y `call` son
     * los dos casos que de verdad se escriben; `retn`/`retf` los desambiguan a
     * mano y son los mismos dos destinos. */
    if (up == "RETN") return find_iclass(t, "RET_NEAR");
    if (up == "RETF") return find_iclass(t, "RET_FAR");
    if (up == "LOOPZ") return find_iclass(t, "LOOPE");
    if (up == "LOOPNZ") return find_iclass(t, "LOOPNE");
    if (const DbIclassRange *r = find_iclass(t, up + "_NEAR")) return r;
    if (const DbIclassRange *r = find_iclass(t, up + "_FAR")) return r;

    /* Condiciones: la raiz dice QUE hace (saltar, asignar, mover) y el resto
     * es la condicion, que es lo unico que cambia de nombre. */
    static const char *const raices[] = {"CMOV", "SET", "J"};
    for (const char *raiz : raices) {
        const size_t n = std::strlen(raiz);
        if (up.size() <= n || up.compare(0, n, raiz) != 0) continue;
        const char *canon = cond_canonica_x86(up.substr(n));
        if (canon == nullptr) break; // la raiz casa: no hay otra que probar
        return find_iclass(t, std::string(raiz) + canon);
    }
    return nullptr;
}

} // namespace

namespace {

/// Ancho (bits) de un registro segun la ISA (0 = desconocido/no restringe).
/// Espeja @c regWidth del analizador (x86 exacto; ARM/RISC-V el ancho real,
/// pero las formas ARM/RISC-V llevan width 0 = "cualquiera", asi que el score
/// no lo restringe).
uint16_t reg_width(Isa isa, const std::string &r) {
    auto pref = [&](const char *p) {
        size_t n = std::strlen(p);
        return r.size() > n && r.compare(0, n, p) == 0 &&
               std::isdigit((unsigned char)r[n]);
    };
    if (isa == Isa::ARM64 || isa == Isa::ARM32) {
        if (r == "sp" || r == "xzr" || r == "lr") return 64;
        if (r == "wzr" || r == "wsp" || r == "pc") return 32;
        if (!r.empty() && (r[0] == 'x') && std::isdigit((unsigned char)r[1]))
            return 64;
        if (!r.empty() && (r[0] == 'w') && std::isdigit((unsigned char)r[1]))
            return 32;
        if (!r.empty() && (r[0] == 'r') && std::isdigit((unsigned char)r[1]))
            return 32; // A32
        if (pref("q") || pref("v")) return 128;
        if (pref("d")) return 64;
        if (pref("s")) return 32;
        if (pref("h")) return 16;
        if (pref("b")) return 8;
        return 0;
    }
    if (isa == Isa::RISCV) {
        static const char *abi[] = {
            "zero", "ra", "sp", "gp", "tp", "fp",  "t0",  "t1", "t2",
            "t3",   "t4", "t5", "t6", "s0", "s1",  "s2",  "s3", "s4",
            "s5",   "s6", "s7", "s8", "s9", "s10", "s11", "a0", "a1",
            "a2",   "a3", "a4", "a5", "a6", "a7"};
        for (const char *a : abi)
            if (r == a) return 64;
        if ((r[0] == 'x' || r[0] == 'f') && r.size() > 1 &&
            std::isdigit((unsigned char)r[1]))
            return 64;
        if (r.size() >= 2 && (r.rfind("ft", 0) == 0 || r.rfind("fs", 0) == 0 ||
                              r.rfind("fa", 0) == 0))
            return 64;
        return 0;
    }
    // x86: anchos exactos.
    auto is = [&](std::initializer_list<const char *> l) {
        for (auto s : l)
            if (r == s) return true;
        return false;
    };
    if (is({"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"}) ||
        (pref("r") && (r.back() != 'd' && r.back() != 'w' && r.back() != 'b')))
        return 64;
    if (is({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}) ||
        (pref("r") && r.back() == 'd'))
        return 32;
    if (is({"ax", "bx", "cx", "dx", "si", "di", "bp", "sp"}) ||
        (pref("r") && r.back() == 'w'))
        return 16;
    if (is({"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "bpl",
            "spl"}) ||
        (pref("r") && r.back() == 'b'))
        return 8;
    if (pref("xmm")) return 128;
    if (pref("ymm")) return 256;
    if (pref("zmm")) return 512;
    if (pref("k")) return 64;
    return 0;
}

} // namespace

ParsedOp parse_operand(Isa isa, const std::string &token) {
    std::string t = token;
    // trim.
    while (!t.empty() && std::isspace((unsigned char)t.front()))
        t.erase(0, 1);
    while (!t.empty() && std::isspace((unsigned char)t.back()))
        t.pop_back();
    std::string low = t;
    for (char &c : low)
        c = static_cast<char>(std::tolower((unsigned char)c));

    // RISC-V: memoria como desplazamiento(reg): 0(a0), -4(sp).
    if (isa == Isa::RISCV) {
        size_t op = low.find('(');
        if (op != std::string::npos && low.back() == ')')
            return ParsedOp{OP_MEM, 0};
    }
    // x86/ARM: memoria [...].
    if (low.find('[') != std::string::npos) return ParsedOp{OP_MEM, 0};
    /* Marcador de operando del compilador (`$0`, `$1`...): es un REGISTRO.
     *
     * Se clasificaba como inmediato -- no empieza por letra ni por digito --, y
     * con eso el emparejador elegia una forma con operando de memoria: un
     * `pext $0, $1, $2` acababa declarando que lee y escribe memoria, que es
     * justo lo que convierte un bloque en una barrera.  Cuando el operando
     * acaba siendo memoria, en el texto lleva sus corchetes y lo coge la regla
     * de arriba; un marcador PELADO siempre es un registro.
     *
     * El `$` a secas y el `$$` de NASM (la direccion de aqui, el principio de
     * la seccion) no son marcadores: llevan digito detras solo los nuestros. */
    if (low.size() > 1 && low[0] == '$' && std::isdigit((unsigned char)low[1]))
        return ParsedOp{OP_REG, 0};
    // inmediato ARM (#imm) o numero.
    std::string num = low;
    if (!num.empty() && num[0] == '#') num.erase(0, 1);
    if (!num.empty() && (std::isdigit((unsigned char)num[0]) ||
                         ((num[0] == '-' || num[0] == '+') && num.size() > 1)))
        return ParsedOp{OP_IMM, 0};
    // registro.
    uint16_t w = reg_width(isa, low);
    if (w || (!low.empty() && std::isalpha((unsigned char)low[0])))
        return ParsedOp{OP_REG, w};
    return ParsedOp{OP_IMM, 0};
}

namespace {

/// trim in-place.
void trim(std::string &s) {
    while (!s.empty() && std::isspace((unsigned char)s.front()))
        s.erase(0, 1);
    while (!s.empty() && std::isspace((unsigned char)s.back()))
        s.pop_back();
}

/// Parte una linea de asm en mnemonico + tokens de operando (respetando
/// @c [...] y @c (...)).  Devuelve false si es vacia o label.
bool split_asm_line(const std::string &line, std::string &mnem,
                    std::vector<std::string> &toks) {
    std::string s = line;
    size_t cm = s.find(';');
    if (cm != std::string::npos) s.resize(cm);
    size_t sl = s.find("//");
    if (sl != std::string::npos) s.resize(sl);
    trim(s);
    if (s.empty() || s.back() == ':') return false;
    size_t sp = s.find_first_of(" \t");
    mnem = sp == std::string::npos ? s : s.substr(0, sp);
    std::string rest = sp == std::string::npos ? "" : s.substr(sp + 1);
    /* Un PREFIJO de repeticion no es una instruccion: es parte del nombre.
     *
     * En el texto se escriben separados (`rep movsb`), pero la base los modela
     * juntos porque son otra instruccion -- `REP_MOVSB` recorre un contador y
     * `MOVSB` copia un elemento --, que es una diferencia de verdad y no un
     * adorno.  Cortando por el primer espacio, el mnemonico salia "rep", que no
     * existe en ninguna tabla: `memcpy_erms` y `memset_erms`, que ES asi como
     * estan escritas, quedaban con cero por ciento de cobertura y con "la base
     * no la conoce" cuando la base si la conoce. */
    {
        std::string bajo = mnem;
        for (char &c : bajo)
            c = static_cast<char>(std::tolower((unsigned char)c));
        /* `lock` es lo contrario: NO cambia de instruccion, obliga a que la que
         * viene detras sea atomica.  La base modela la instruccion, asi que el
         * prefijo se descarta y se responde por ella; sin esto, un `lock xadd`
         * salia como el mnemonico "lock", que no existe en ninguna tabla. */
        if ((bajo == "lock" || bajo == "xacquire" || bajo == "xrelease") &&
            !rest.empty()) {
            const size_t sp2 = rest.find_first_of(" \t");
            mnem = (sp2 == std::string::npos) ? rest : rest.substr(0, sp2);
            rest = (sp2 == std::string::npos) ? "" : rest.substr(sp2 + 1);
            bajo = mnem;
            for (char &c : bajo)
                c = static_cast<char>(std::tolower((unsigned char)c));
        }
        /* `repz` y `repnz` son otra forma de escribir `repe` y `repne`; la base
         * guarda una sola. */
        if (bajo == "repz")
            mnem = "repe";
        else if (bajo == "repnz")
            mnem = "repne";
        const bool es_prefijo =
            (bajo == "rep" || bajo == "repe" || bajo == "repz" ||
             bajo == "repne" || bajo == "repnz");
        if (es_prefijo && !rest.empty()) {
            const size_t sp2 = rest.find_first_of(" \t");
            const std::string siguiente =
                (sp2 == std::string::npos) ? rest : rest.substr(0, sp2);
            if (!siguiente.empty()) {
                mnem += "_";
                mnem += siguiente;
                rest = (sp2 == std::string::npos) ? "" : rest.substr(sp2 + 1);
            }
        }
    }
    toks.clear();
    std::string cur;
    int depth = 0;
    auto flush = [&]() {
        trim(cur);
        if (!cur.empty()) toks.push_back(cur);
        cur.clear();
    };
    for (char c : rest) {
        if (c == '[' || c == '(')
            ++depth;
        else if (c == ']' || c == ')')
            --depth;
        if (c == ',' && depth == 0)
            flush();
        else
            cur += c;
    }
    flush();
    return true;
}

/// Registro canonico (colapsa alias de ancho) para el grafo de dependencias.
std::string canon_reg(Isa isa, const std::string &tok) {
    std::string low = tok;
    for (char &c : low)
        c = static_cast<char>(std::tolower((unsigned char)c));
    if (isa == Isa::RISCV) {
        // nombres ABI -> registro fisico (a0=x10, ra=x1, ...).
        static const std::pair<const char *, const char *> abi[] = {
            {"zero", "x0"}, {"ra", "x1"},  {"sp", "x2"},  {"gp", "x3"},
            {"tp", "x4"},   {"fp", "x8"},  {"t0", "x5"},  {"t1", "x6"},
            {"t2", "x7"},   {"s0", "x8"},  {"s1", "x9"},  {"a0", "x10"},
            {"a1", "x11"},  {"a2", "x12"}, {"a3", "x13"}, {"a4", "x14"},
            {"a5", "x15"},  {"a6", "x16"}, {"a7", "x17"}, {"s2", "x18"},
            {"s3", "x19"},  {"s4", "x20"}, {"s5", "x21"}, {"s6", "x22"},
            {"s7", "x23"},  {"s8", "x24"}, {"s9", "x25"}, {"s10", "x26"},
            {"s11", "x27"}, {"t3", "x28"}, {"t4", "x29"}, {"t5", "x30"},
            {"t6", "x31"}};
        for (const auto &p : abi)
            if (low == p.first) return p.second;
        return low;
    }
    /* x86 y ARM (colapsa rax/eax, x0/w0...).  Con la arquitectura de la ISA que
     * se esta analizando, NO la del objetivo activo: la version de un argumento
     * la resuelve por el entorno, asi que analizando una linea de ARM mientras
     * se compila para x86 un `x0` no canonicalizaba a nada y el registro
     * escrito se perdia en silencio -- la forma salia resuelta y sin decir que
     * escribe --.
     *
     * Es justo el motivo por el que existe la version de dos argumentos, y lo
     * dice su propia cabecera: ahi el arch es un dato del ANALISIS, no del
     * entorno. */
    const char *arch = isa == Isa::ARM64   ? "arm64"
                       : isa == Isa::ARM32 ? "arm32"
                                           : "x86_64";
    return vx::asm_canonical_reg(low, arch);
}

/// Registros que aparecen dentro de un operando de memoria (direccion).
void addr_regs(Isa isa, const std::string &tok, std::vector<std::string> &out) {
    // extrae subtokens alfanumericos y quedate con los que son registros.
    std::string cur;
    auto push = [&]() {
        if (!cur.empty()) {
            uint16_t w = 0;
            (void)w;
            // reusa parse_operand para saber si es registro.
            ParsedOp p = parse_operand(isa, cur);
            if (p.kind == OP_REG) out.push_back(canon_reg(isa, cur));
            cur.clear();
        }
    };
    for (char c : tok) {
        if (std::isalnum((unsigned char)c) || c == '_' || c == '.')
            cur += c;
        else
            push();
    }
    push();
}

} // namespace

const char *isa_name(Isa isa) {
    switch (isa) {
    case Isa::X86: return "x86";
    case Isa::ARM64: return "arm64";
    case Isa::ARM32: return "arm32";
    case Isa::RISCV: return "riscv";
    }
    return "";
}

bool has_mnemonic(const std::string &line) {
    std::string mnem;
    std::vector<std::string> toks;
    return split_asm_line(line, mnem, toks);
}

int32_t match_asm_line(Isa isa, const std::string &line) {
    std::string mnem;
    std::vector<std::string> toks;
    if (!split_asm_line(line, mnem, toks)) return -1;
    std::vector<ParsedOp> ops;
    ops.reserve(toks.size());
    for (const auto &t : toks)
        ops.push_back(parse_operand(isa, t));
    return match(isa, mnem, ops);
}

int32_t match(Isa isa, const std::string &mnemonic,
              const std::vector<ParsedOp> &ops, bool *por_operandos) {
    const IsaData t = tables_for(isa);
    if (!t.forms) return -1;
    std::string up = mnemonic;
    for (char &c : up)
        c = static_cast<char>(std::toupper((unsigned char)c));
    const DbIclassRange *r = find_iclass_escrito(t, isa, up);
    if (!r) return -1; // mnemonico no existe
    int32_t best = -1;
    int best_s = -1;
    std::vector<const DbOperand *> fo;
    for (uint32_t fid = r->first_fid; fid < r->first_fid + r->count; ++fid) {
        explicit_ops(t, t.forms[fid], fo);
        int s = score_ops(ops, fo);
        if (s > best_s) {
            best_s = s;
            best = static_cast<int32_t>(fid);
        }
    }
    /* El mnemonico existe: si nada caso por operandos, vale la primera del
     * rango
     * -- sirve para saber que la instruccion EXISTE --, pero se dice que fue
     * por el nombre y no por la forma.  Devolver las dos cosas iguales ya
     * mordio dos veces: un `movsd [rdi], xmm0` cogia la forma de CADENA porque
     * la de SSE no casaba por aridad, y con ella sus efectos -- los de otra
     * instruccion --. Quien necesite certeza pregunta; quien solo quiera saber
     * si existe, no. */
    if (por_operandos != nullptr) *por_operandos = best >= 0;
    return best >= 0 ? best : static_cast<int32_t>(r->first_fid);
}

const char *iclass_name(Isa isa, int32_t form_id) {
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return "";
    return t.str[t.forms[form_id].iclass];
}

uint16_t overlay_of(Isa isa, int32_t form_id) {
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return 0;
    return t.forms[form_id].overlay;
}

const char *ext_of(Isa isa, int32_t form_id) {
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return "";
    return t.str[t.forms[form_id].ext];
}

bool explicit_operand(Isa isa, int32_t form_id, size_t idx, bool &reads,
                      bool &writes) {
    DbOpKind kind = OP_REG; // el rol sin la clase: la ignora quien no la pida.
    return explicit_operand(isa, form_id, idx, reads, writes, kind);
}

bool explicit_operand(Isa isa, int32_t form_id, size_t idx, bool &reads,
                      bool &writes, DbOpKind &kind) {
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return false;
    const DbForm &f = t.forms[form_id];
    size_t seen = 0;
    for (uint8_t i = 0; i < f.ops_count; ++i) {
        const DbOperand &o = t.ops[f.ops_off + i];
        // bit2 = implicito, bit3 = suprimido: no se escriben en el texto.
        if ((o.flags & 0x04) != 0 || (o.flags & 0x08) != 0) continue;
        if (seen == idx) {
            reads = (o.flags & 0x01) != 0;
            writes = (o.flags & 0x02) != 0;
            kind = static_cast<DbOpKind>(o.kind);
            return true;
        }
        ++seen;
    }
    return false;
}

bool memory_of(Isa isa, int32_t form_id, bool &reads, bool &writes) {
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return false;
    const DbForm &f = t.forms[form_id];
    reads = false;
    writes = false;
    bool mem_operand = false;
    for (uint8_t i = 0; i < f.ops_count; ++i) {
        const DbOperand &o = t.ops[f.ops_off + i];
        if (o.kind != OP_MEM) continue;
        mem_operand = true;
        /* El sentido lo da el ROL del operando de memoria, no el mnemonico.  Se
         * mira el flag del propio operando y tambien la mascara de la forma:
         * son la misma cosa dicha dos veces en el generador, y quedarse con una
         * sola dejaria de responder el dia que una de las dos falte. */
        if ((o.flags & 0x01) != 0 || ((f.rmask >> i) & 1) != 0) reads = true;
        if ((o.flags & 0x02) != 0 || ((f.wmask >> i) & 1) != 0) writes = true;
    }
    /* Memoria que la forma toca sin nombrarla en el texto (`push`, `pop`): se
     * responde en los dos sentidos.  Es lo unico honesto sin saber cual, y cae
     * del lado que no habilita transformaciones. */
    if (!mem_operand && (f.memflags & 0x01) != 0) {
        reads = true;
        writes = true;
    }
    return true;
}

std::vector<ImplicitOperand> implicit_operands(Isa isa, int32_t form_id) {
    std::vector<ImplicitOperand> out;
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return out;
    const DbForm &f = t.forms[form_id];
    for (uint8_t i = 0; i < f.ops_count; ++i) {
        const DbOperand &o = t.ops[f.ops_off + i];
        // bit2 = implicito, bit3 = suprimido: los dos son "no esta en el
        // texto".
        if ((o.flags & 0x0C) == 0) continue;
        if (o.kind != OP_REG && o.kind != OP_MEM) continue; // banderas: aparte
        ImplicitOperand io;
        io.is_memory = o.kind == OP_MEM;
        io.reads = (o.flags & 0x01) != 0;
        io.writes = (o.flags & 0x02) != 0;
        if (!io.is_memory) {
            /* El conjunto de registros de un operando implicito NOMBRA el
             * registro concreto (`AX`, `EDX`, `RSP`).  Se canonicaliza para que
             * `AX`, `EAX` y `RAX` sean el mismo registro fisico, que es lo que
             * le importa a quien consume el efecto.
             *
             * Algunos nombran un conjunto interno que no es un registro
             * (`MSRS`): ahi se deja vacio, y quien lo lea sabe que hay un
             * efecto cuyo sitio no se puede nombrar -- que es un dato, no un
             * fallo. */
            const char *arch = isa == Isa::ARM64   ? "arm64"
                               : isa == Isa::ARM32 ? "arm32"
                               : isa == Isa::RISCV ? "riscv"
                                                   : "x86_64";
            const char *nombre = t.str[o.regset];
            io.reg = asm_canonical_reg(nombre, arch);
            /* Lo que no es un registro general SI es estado con nombre: `cr0`,
             * `gdtr`, `msrs`, `mxcsr`, `rip`, la pila del x87.  Se conserva el
             * nombre en minusculas en vez de perderlo: un efecto sin sitio
             * obliga a suponer lo peor, y uno con sitio solo choca con quien
             * toque ese mismo sitio. */
            if (io.reg.empty() && nombre != nullptr)
                for (const char *p = nombre; *p != '\0'; ++p)
                    io.state.push_back(
                        static_cast<char>(std::tolower((unsigned char)*p)));
        }
        out.push_back(std::move(io));
    }
    return out;
}

bool form_is_modelable(Isa isa, int32_t form_id) {
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return false;
    const DbForm &f = t.forms[form_id];
    const char *arch = isa == Isa::ARM64   ? "arm64"
                       : isa == Isa::ARM32 ? "arm32"
                       : isa == Isa::RISCV ? "riscv"
                                           : "x86_64";
    for (uint8_t i = 0; i < f.ops_count; ++i) {
        const DbOperand &o = t.ops[f.ops_off + i];
        if (!op_kind_is_textual(o.kind)) continue;
        // bit2 = implicito, bit3 = suprimido: no se escriben en el texto.
        if ((o.flags & 0x0C) == 0) continue;
        (void)arch;
        (void)o;
        /* Un registro implicito ya NO impide modelarla: la forma dice CUAL es
         * (ver @ref implicit_operands), asi que se sabe que toca y donde.
         *
         * Y uno cuyo nombre no es un registro -- `MSRS`, `MXCSR` -- tampoco:
         * sus efectos sobre registros y memoria siguen capturados, y lo que no
         * se puede nombrar se trata como que ORDENA, o sea que nada se mueve a
         * traves.  Rendirse entero seria tirar lo que si se sabe.
         *
         * Antes bastaba con que hubiera UNO para rendirse, y eso dejaba fuera a
         * las 271 instrucciones de x86 que nadie conocia: justo las que hacen
         * algo con `rdx:rax`.  No es que faltara el dato -- estaba en la forma
         * --: es que no se miraba. */
    }
    return true;
}

bool flag_names_of(Isa isa, int32_t form_id, std::vector<std::string> &reads,
                   std::vector<std::string> &writes) {
    reads.clear();
    writes.clear();
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return false;
    /* Sin leyenda no se puede nombrar ningun bit.  Se responde que no se sabe
     * -- y no que no toca ninguna --, que son cosas distintas: lo segundo
     * permitiria mover una comparacion a traves de algo que la destruye. */
    if (t.flag_names == nullptr || t.flag_count == 0) return false;
    const DbForm &f = t.forms[form_id];
    for (unsigned b = 0; b < t.flag_count && b < 16; ++b) {
        if (t.flag_names[b] == nullptr) continue;
        if ((f.rflags_set >> b) & 1u) reads.emplace_back(t.flag_names[b]);
        if ((f.wflags_set >> b) & 1u) writes.emplace_back(t.flag_names[b]);
    }
    return true;
}

bool flag_names_of_mnemonic(Isa isa, const std::string &mnemonic,
                            std::vector<std::string> &reads,
                            std::vector<std::string> &writes) {
    reads.clear();
    writes.clear();
    const IsaData t = tables_for(isa);
    if (!t.forms || t.flag_names == nullptr || t.flag_count == 0) return false;
    /* La condicion de arm va PEGADA al mnemonico (`b.eq`) y la base nombra la
     * clase sin ella (`B`): se separa para buscarla, y el hecho de que
     * estuviera se usa mas abajo para elegir entre la rama que lee banderas y
     * la que no. */
    const size_t punto = mnemonic.find('.');
    const std::string base = (punto != std::string::npos && punto > 0)
                                 ? mnemonic.substr(0, punto)
                                 : mnemonic;
    std::string up;
    up.reserve(base.size());
    for (char c : base)
        up.push_back(static_cast<char>(std::toupper((unsigned char)c)));
    const DbIclassRange *r = find_iclass_escrito(t, isa, up);
    if (r == nullptr || r->count == 0) return false;
    /* Las formas que TIENEN el dato tienen que coincidir.  Si discrepan no se
     * contesta: elegir una seria inventar cual de ellas se escribio.
     *
     * Las que no lo traen se saltan, no cuentan como discrepancia: de las seis
     * formas de `ADDS` solo tres traen el suyo -- el pseudocodigo de las otras
     * no se pudo resolver --, y tratar ese hueco como una respuesta distinta
     * dejaria sin contestar a un mnemonico sobre el que las tres que hablan
     * dicen lo mismo.  Una forma que no sabe no contradice a las que si. */
    /* Cuando el mnemonico lleva CONDICION (`b.eq`), solo son candidatas las
     * formas que leen banderas: la condicion es lo que las lee, y la base
     * agrupa la rama condicional y la incondicional bajo el mismo nombre (`B`).
     * Sin esta restriccion las dos discrepan y no se contesta; con ella se
     * contesta lo que dice la que corresponde.  No es elegir por conveniencia:
     * es que la sintaxis ya dijo cual de las dos se escribio. */
    const bool condicional = mnemonic.find('.') != std::string::npos;
    uint16_t w = 0, rd = 0;
    bool alguna = false;
    for (uint32_t k = 0; k < r->count; ++k) {
        const DbForm &f = t.forms[r->first_fid + k];
        if (condicional && f.rflags_set == 0) continue; // no es la condicional
        if (f.wflags_set == 0 && f.rflags_set == 0) continue; // no sabe
        if (!alguna) {
            w = f.wflags_set;
            rd = f.rflags_set;
            alguna = true;
        } else if (f.wflags_set != w || f.rflags_set != rd) {
            return false;
        }
    }
    if (!alguna) return false; // sin dato: no es lo mismo que no tocar ninguna
    for (unsigned b = 0; b < t.flag_count && b < 16; ++b) {
        if (t.flag_names[b] == nullptr) continue;
        if ((rd >> b) & 1u) reads.emplace_back(t.flag_names[b]);
        if ((w >> b) & 1u) writes.emplace_back(t.flag_names[b]);
    }
    return true;
}

bool flags_of(Isa isa, int32_t form_id, bool &reads, bool &writes) {
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return false;
    const DbForm &f = t.forms[form_id];
    // bit2 = escribe banderas, bit3 = las lee (mismo campo que la memoria).
    writes = (f.memflags & 0x04) != 0;
    reads = (f.memflags & 0x08) != 0;
    return true;
}

const char *isa_set_of(Isa isa, int32_t form_id) {
    const IsaData t = tables_for(isa);
    if (!t.forms || form_id < 0 ||
        static_cast<unsigned>(form_id) >= t.form_count)
        return "";
    return t.str[t.forms[form_id].isa_set];
}

std::string requisito_de_mnemonico(Isa isa, const std::string &mnemonic) {
    const IsaData t = tables_for(isa);
    if (!t.forms || !t.iclass) return std::string();
    std::string up = mnemonic;
    for (char &c : up)
        c = static_cast<char>(std::toupper((unsigned char)c));
    const DbIclassRange *r = find_iclass_escrito(t, isa, up);
    if (!r || r->count == 0) return std::string();
    // Se compara el RASGO, no el conjunto en crudo: las formas de `vmovdqu64`
    // son AVX512F_128, _256 y _512, tres conjuntos distintos que son el mismo
    // rasgo -- quien tiene AVX512F lo tiene para los tres anchos.  Comparando
    // en crudo, ninguna instruccion vectorial habria respondido nunca.
    //
    // Lo que si obliga a callar es que el rasgo difiera de verdad: un mnemonico
    // con formas SSE y formas AVX-512 no permite decir cual fallo sin mirar los
    // operandos, y aqui no hay operandos que mirar.
    std::string comun = nombre_de_rasgo(t.str[t.forms[r->first_fid].isa_set]);
    for (uint32_t i = 1; i < r->count; ++i) {
        if (nombre_de_rasgo(t.str[t.forms[r->first_fid + i].isa_set]) != comun)
            return std::string();
    }
    return comun;
}

std::string nombre_de_rasgo(const std::string &isa_set) {
    if (isa_set.empty() || isa_set == "-") return "";
    // El conjunto base no es un rasgo: nadie lo declara porque nadie carece de
    // el.
    if (isa_set == "I86" || isa_set == "I386" || isa_set == "LONGMODE" ||
        isa_set == "PPRO" || isa_set == "PENTIUMREAL")
        return "";
    static const char *const anchos[] = {"_512", "_256", "_128", "_SCALAR"};
    std::string s = isa_set;
    for (const char *suf : anchos) {
        const size_t n = std::strlen(suf);
        if (s.size() > n && s.compare(s.size() - n, n, suf) == 0) {
            s.resize(s.size() - n);
            break;
        }
    }
    return s;
}

uint32_t form_count(Isa isa) {
    return tables_for(isa).form_count;
}

// -------------------------------------------------------------------------
// Capa de coste: latencia + puertos por microarquitectura.
// -------------------------------------------------------------------------

namespace {
CostData cost_for(Isa isa) {
    switch (isa) {
    case Isa::X86: return cost_x86();
    case Isa::ARM64: return cost_arm64();
    case Isa::ARM32: return cost_arm32();
    case Isa::RISCV: return cost_riscv();
    }
    return {};
}
} // namespace

uint32_t microarch_count(Isa isa) {
    return cost_for(isa).count;
}

const char *microarch_name(Isa isa, uint32_t ua_id) {
    const CostData c = cost_for(isa);
    return ua_id < c.count ? c.uarchs[ua_id].name : "";
}

int32_t microarch_by_name(Isa isa, const std::string &name) {
    const CostData c = cost_for(isa);
    for (uint32_t i = 0; i < c.count; ++i)
        if (name == c.uarchs[i].name) return static_cast<int32_t>(i);
    return -1;
}

AsmCost cost(Isa isa, int32_t form_id, uint32_t ua_id) {
    AsmCost r;
    const CostData c = cost_for(isa);
    if (ua_id >= c.count || form_id < 0) return r;
    const MicroarchData &m = c.uarchs[ua_id];
    if (static_cast<uint32_t>(form_id) >= m.form_count) return r;
    int16_t cid = m.form_class[form_id];
    if (cid < 0) return r; // no cronometrada en esta uarch
    const AsmClass &cl = m.classes[cid];
    r.found = true;
    r.recip_tp = cl.recip_tp;
    r.latency = cl.latency;
    r.div_cycles = cl.div_cycles;
    r.uops = cl.uops;
    r.microcoded = (cl.flags & 0x1) != 0;
    r.macro_fusible = (cl.flags & 0x2) != 0;
    r.ports = m.slots + cl.ports_off;
    r.ports_count = cl.ports_count;
    r.port_names = m.port_names;
    return r;
}

// -------------------------------------------------------------------------
// Capa de features por CPU (que extensiones de ISA admite cada core).
// -------------------------------------------------------------------------

namespace {
FeatData feat_for(Isa isa) {
    switch (isa) {
    case Isa::X86: return feat_x86();
    case Isa::ARM64:
    case Isa::ARM32: return feat_arm(); // A64 y A32/T32 comparten features.
    case Isa::RISCV: return feat_riscv();
    }
    return {};
}
} // namespace

uint32_t cpu_count(Isa isa) {
    return feat_for(isa).cpu_count;
}

const char *cpu_name(Isa isa, uint32_t cpu_id) {
    const FeatData f = feat_for(isa);
    return cpu_id < f.cpu_count ? f.cpus[cpu_id].name : "";
}

int32_t cpu_by_name(Isa isa, const std::string &name) {
    const FeatData f = feat_for(isa);
    for (uint32_t i = 0; i < f.cpu_count; ++i)
        if (name == f.cpus[i].name) return static_cast<int32_t>(i);
    return -1;
}

bool cpu_has_feature(Isa isa, uint32_t cpu_id, const std::string &feature) {
    const FeatData f = feat_for(isa);
    if (cpu_id >= f.cpu_count) return false;
    const CpuFeatures &c = f.cpus[cpu_id];
    for (uint16_t i = 0; i < c.feat_count; ++i)
        if (feature == f.feat_names[c.feats[i]]) return true;
    return false;
}

AsmBlockCost analyze_asm_cost(Isa isa, const std::string &body,
                              uint32_t ua_id) {
    AsmBlockCost out;
    // presion por puerto acumulada por NOMBRE (dos instrucciones distintas
    // pueden compartir grupo de puertos).
    std::vector<std::pair<std::string, float>> pressure;
    auto add_port = [&](const std::string &name, float uops) {
        for (auto &p : pressure)
            if (p.first == name) {
                p.second += uops;
                return;
            }
        pressure.emplace_back(name, uops);
    };
    float tp_sum = 0.0f;

    size_t i = 0;
    while (i <= body.size()) {
        size_t nl = body.find('\n', i);
        std::string line = body.substr(
            i, nl == std::string::npos ? std::string::npos : nl - i);
        i = (nl == std::string::npos) ? body.size() + 1 : nl + 1;
        int32_t fid = match_asm_line(isa, line);
        if (fid < 0) {
            // ¿linea con contenido pero mnemonico desconocido?  cuenta como
            // instruccion no emparejada (para la completitud).
            std::string t = line;
            size_t c = t.find_first_of(";");
            if (c != std::string::npos) t.resize(c);
            size_t s2 = t.find("//");
            if (s2 != std::string::npos) t.resize(s2);
            while (!t.empty() && std::isspace((unsigned char)t.front()))
                t.erase(0, 1);
            while (!t.empty() && std::isspace((unsigned char)t.back()))
                t.pop_back();
            if (!t.empty() && t.back() != ':') ++out.instr_count;
            continue;
        }
        ++out.instr_count;
        ++out.matched;
        AsmCost c = cost(isa, fid, ua_id);
        if (!c.found) continue;
        ++out.costed;
        out.total_uops += c.uops;
        out.latency_sum += c.latency;
        tp_sum += c.recip_tp;
        for (uint8_t k = 0; k < c.ports_count; ++k) {
            const AsmPortSlot &ps = c.ports[k];
            add_port(c.port_names[ps.port], ps.uops);
        }
    }
    // throughput = max(puerto mas cargado, suma de recip_tp) -- cota inferior
    // de ciclos del bloque bien planificado (ejecucion paralela por puertos).
    float max_port = 0.0f;
    for (const auto &p : pressure)
        max_port = std::max(max_port, p.second);
    out.throughput = std::max(max_port, tp_sum);
    out.port_pressure = std::move(pressure);
    return out;
}

// -------------------------------------------------------------------------
// Scheduling: semantica por instruccion + hazards + list scheduling.
// -------------------------------------------------------------------------

namespace {
bool contains(const std::vector<std::string> &v, const std::string &x) {
    for (const auto &e : v)
        if (e == x) return true;
    return false;
}

/// Indica si un nombre de registro es el CONTADOR DE PROGRAMA.
///
/// Son los nombres con los que lo llama cada fuente; no hay mas de cuatro
/// porque no hay mas maneras de llamarlo.  Escribirlo es la definicion de
/// transferir el control, y de ahi sale que nada se pueda mover al otro lado.
bool es_contador_de_programa(const std::string &reg) {
    std::string low;
    low.reserve(reg.size());
    for (char c : reg)
        low.push_back(static_cast<char>(std::tolower((unsigned char)c)));
    return low == "rip" || low == "eip" || low == "ip" || low == "pc";
}

/// Todo bit de overlay que impide reordenar (barrera dura).
const uint16_t OVL_BARRIER_ANY = OVL_BARRIER | OVL_SERIALIZING | OVL_ATOMIC |
                                 OVL_LL_SC | OVL_MEM_ACQUIRE | OVL_MEM_RELEASE |
                                 OVL_MEM_SEQ_CST | OVL_NO_REORDER | OVL_BRANCH |
                                 OVL_CALL | OVL_RET | OVL_SYSCALL;
} // namespace

AsmInsnSem asm_insn_sem(Isa isa, const std::string &line, uint32_t ua_id) {
    AsmInsnSem s;
    s.text = line;
    std::string mnem;
    std::vector<std::string> toks;
    if (!split_asm_line(line, mnem, toks)) {
        s.form_id = -1; // label / vacia: no es instruccion
        return s;
    }
    std::vector<ParsedOp> ops;
    ops.reserve(toks.size());
    for (const auto &t : toks)
        ops.push_back(parse_operand(isa, t));
    /* Si la forma caso POR OPERANDOS lo dice el emparejador, que es quien
     * conoce la regla entera -- incluida la de que se pueden omitir los
     * opcionales del final --.  Aqui se recalculaba con una igualdad estricta
     * de aridad, asi que una forma que el emparejador SI habia resuelto se
     * declaraba no modelada: dos sitios calculando lo mismo y solo uno enterado
     * de la regla nueva. */
    bool caso_por_operandos = false;
    int32_t fid = match(isa, mnem, ops, &caso_por_operandos);
    s.form_id = fid;
    if (fid < 0) {        // mnemonico desconocido
        s.barrier = true; // CONSERVADOR: no se reordena.
        s.modeled = false;
        return s;
    }
    const IsaData tb = tables_for(isa);
    const DbForm &f = tb.forms[fid];
    s.barrier = (f.overlay & OVL_BARRIER_ANY) != 0;
    s.writes_flags = (f.memflags & 0x04) != 0;
    s.reads_flags = (f.memflags & 0x08) != 0;
    s.writes_flags_set = f.wflags_set;
    s.reads_flags_set = f.rflags_set;
    s.latency = cost(isa, fid, ua_id).latency;

    // Operandos EXPLICITOS del form (no implicit/suppressed, no flags)
    // alineados con los tokens de la linea.  Si hay registros IMPLICITOS, la
    // aridad no casa o toca memoria no capturada -> CONSERVADOR (no modelada).
    std::vector<int> expl;
    bool implicit_reg = false;
    bool mem_operand = false;
    for (unsigned i = 0; i < f.ops_count; ++i) {
        const DbOperand &o = tb.ops[f.ops_off + i];
        if (!op_kind_is_textual(o.kind)) continue;
        bool impl = (o.flags & 0x0C) != 0;
        if (impl) {
            if (o.kind == OP_REG) implicit_reg = true;
            continue;
        }
        if (o.kind == OP_MEM) mem_operand = true;
        expl.push_back(static_cast<int>(i));
    }
    /* La aridad la da el EMPAREJADOR, no una igualdad aparte: es quien sabe que
     * los opcionales del final se pueden omitir.  Con la igualdad estricta, un
     * `adds x0, x1, x2` -- cuya forma declara ademas un desplazamiento opcional
     * -- salia no modelado aunque la forma estuviera perfectamente resuelta. */
    bool arity_ok = caso_por_operandos;
    // memoria implicita (memflags bit0 sin operando mem, p.ej. push/pop) -> no
    // modelada.
    bool implicit_mem = (f.memflags & 0x01) != 0 && !mem_operand;
    /* Los operandos IMPLICITOS, leidos de la propia forma.
     *
     * Un registro implicito ya no descalifica la instruccion: la forma dice
     * CUAL es -- que una `div` usa `rdx:rax`, que una `rdmsr` escribe `eax:edx`
     * y lee `ecx` --, asi que se anota igual que si estuviera escrito. Rendirse
     * aqui era dejar sin modelar justo a las instrucciones que tocan registros
     * que nadie ve venir, que son las peligrosas: quien crea que `rdx` sigue
     * valiendo lo de antes despues de una `div` se equivoca.
     *
     * Lo que no se puede situar es un implicito cuyo nombre no es un registro
     * (`MSRS` y demas conjuntos internos).  Ahi si se marca como no modelada:
     * hay un efecto real en un sitio que no se puede nombrar. */
    bool mem_implicita_vista = false;
    for (const ImplicitOperand &io : implicit_operands(isa, fid)) {
        if (io.is_memory) {
            mem_implicita_vista = true;
            if (io.reads) s.reads_mem = true;
            if (io.writes) s.writes_mem = true;
            continue;
        }
        /* Registro general o ESTADO con nombre: los dos son efectos concretos y
         * los dos se anotan.  Una instruccion privilegiada no es una caja negra
         * -- `wrmsr` escribe `msrs`, `lgdt` escribe `gdtr`, `stmxcsr` lee
         * `mxcsr` --, y con el nombre delante solo choca con quien toque ese
         * mismo sitio.  Sin el, habria que dejar de mover todo a su alrededor.
         */
        const std::string &donde = io.reg.empty() ? io.state : io.reg;
        if (donde.empty()) continue;
        /* Quien escribe el CONTADOR DE PROGRAMA transfiere el control, y nada
         * se puede mover al otro lado: una llamada no dice en su forma que se
         * lleva por delante los registros que la convencion le deja usar, y un
         * salto condicional decide si lo de despues llega a ejecutarse.
         *
         * El dato es de la propia base -- `call`, `ret` y los saltos declaran
         * `rip` como operando implicito escrito --, no una lista de mnemonicos
         * escrita aparte.  El campo overlay que lo diria (rama/call/ret) viene
         * vacio de la fuente en x86, asi que se lee de donde SI esta. */
        if (io.writes && es_contador_de_programa(donde)) s.barrier = true;
        std::vector<std::string> &lee =
            io.reg.empty() ? s.reads_state : s.reads;
        std::vector<std::string> &escribe =
            io.reg.empty() ? s.writes_state : s.writes;
        if (io.reads) lee.push_back(donde);
        if (io.writes) escribe.push_back(donde);
    }
    (void)implicit_reg; // ya no descalifica: la forma dice cual es
    /* Memoria que la forma toca sin decir por donde y sin operando implicito
     * que la describa: ahi no se sabe ni el sentido, y se suponen los dos. */
    if (implicit_mem && !mem_implicita_vista) {
        s.reads_mem = true;
        s.writes_mem = true;
    }
    s.modeled = arity_ok;

    if (arity_ok) {
        /* Hasta donde llegan los TOKENS: la forma puede declarar mas operandos
         * que los escritos -- los opcionales omitidos --, y recorrerlos todos
         * leeria fuera de la linea. */
        for (size_t k = 0; k < expl.size() && k < toks.size(); ++k) {
            int i = expl[k];
            const DbOperand &o = tb.ops[f.ops_off + i];
            bool rd = (f.rmask >> i) & 1;
            bool wr = (f.wmask >> i) & 1;
            if (o.kind == OP_REG) {
                /* Un marcador `$N` se conserva TAL CUAL: no canonicaliza a
                 * ningun registro -- todavia no hay ninguno elegido --, y
                 * meterlo por el canonicalizador devolvia una cadena vacia que
                 * acababa en la lista de escritos.  Un nombre vacio no dice
                 * nada y ademas se cuela como si fuera un registro mas. */
                const std::string &tok = toks[k];
                std::string cr = (tok.size() > 1 && tok[0] == '$' &&
                                  std::isdigit((unsigned char)tok[1]))
                                     ? tok
                                     : canon_reg(isa, tok);
                if (cr.empty()) continue; // no se pudo nombrar: no se inventa
                if (rd) s.reads.push_back(cr);
                if (wr) s.writes.push_back(cr);
            } else if (o.kind == OP_MEM) {
                if (rd) s.reads_mem = true;
                if (wr) s.writes_mem = true;
                addr_regs(isa, toks[k],
                          s.reads); // los regs de direccion se leen
            }
        }
    }
    if (implicit_mem) { // conservador: asume R/W memoria
        s.reads_mem = true;
        s.writes_mem = true;
    }
    return s;
}

bool asm_dep_conflict(const AsmInsnSem &a, const AsmInsnSem &b) {
    // barrera o no-modelada -> siempre conflicto (no se reordena alrededor).
    if (a.barrier || b.barrier || !a.modeled || !b.modeled) return true;
    // memoria: si alguna ESCRIBE y la otra toca memoria (no se sabe si
    // solapan).
    bool amem = a.reads_mem || a.writes_mem;
    bool bmem = b.reads_mem || b.writes_mem;
    if ((a.writes_mem && bmem) || (b.writes_mem && amem)) return true;
    /* Banderas: WAW / WAR / RAW, pero POR BANDERA cuando se sabe cuales.
     *
     * Con el bit grueso, cualquier par que tocara banderas chocaba: un `inc` --
     * que no toca el acarreo -- estorbaba al `adc` que lo consume, y dos `cmp`
     * sobre valores distintos se daban por dependientes.  Con las mascaras solo
     * choca lo que comparte una bandera concreta.
     *
     * Si alguna de las dos no trae el detalle -- otra ISA, o una forma sin dato
     * -- se cae al bit grueso, que sigue siendo cierto: mejor estorbar de mas
     * que dejar pasar un reorden que rompe. */
    const bool detalle = (a.writes_flags_set | a.reads_flags_set) != 0 &&
                         (b.writes_flags_set | b.reads_flags_set) != 0;
    if (detalle) {
        if ((a.writes_flags_set & (b.reads_flags_set | b.writes_flags_set)) !=
            0)
            return true;
        if ((b.writes_flags_set & a.reads_flags_set) != 0) return true;
    } else if ((a.writes_flags && (b.reads_flags || b.writes_flags)) ||
               (b.writes_flags && a.reads_flags)) {
        return true;
    }
    // registros: RAW (a escribe -> b lee), WAW (ambos escriben),
    // WAR (a lee -> b escribe).
    for (const auto &w : a.writes)
        if (contains(b.reads, w) || contains(b.writes, w)) return true;
    for (const auto &w : b.writes)
        if (contains(a.reads, w)) return true;
    /* Y el ESTADO del procesador, con las mismas tres reglas: `cr0`, `gdtr`,
     * `msrs`, `mxcsr`, la pila del x87.  Es lo que hace que modelarlo sirva de
     * algo -- dos privilegiadas que tocan estados distintos no se estorban --,
     * y lo que impide que una `wrmsr` se cuele por delante de la `rdmsr` que
     * lee lo que acaba de escribir. */
    for (const auto &w : a.writes_state)
        if (contains(b.reads_state, w) || contains(b.writes_state, w))
            return true;
    for (const auto &w : b.writes_state)
        if (contains(a.reads_state, w)) return true;
    return false;
}

AsmSchedule schedule_asm_block(Isa isa, const std::string &body,
                               uint32_t ua_id) {
    AsmSchedule out;
    // parte en instrucciones (ignora labels/vacias).
    std::vector<AsmInsnSem> sem;
    size_t i = 0;
    while (i <= body.size()) {
        size_t nl = body.find('\n', i);
        std::string line = body.substr(
            i, nl == std::string::npos ? std::string::npos : nl - i);
        i = (nl == std::string::npos) ? body.size() + 1 : nl + 1;
        std::string mnem;
        std::vector<std::string> toks;
        if (!split_asm_line(line, mnem, toks)) continue; // label / vacia
        sem.push_back(asm_insn_sem(isa, line, ua_id));
    }
    const uint32_t n = static_cast<uint32_t>(sem.size());
    for (uint32_t k = 0; k < n; ++k)
        out.order.push_back(k);
    if (n < 2) return out;

    // planifica por SEGMENTOS: una barrera corta el bloque (nada la cruza).
    std::vector<uint32_t> result;
    uint32_t seg_start = 0;
    auto sched_segment = [&](uint32_t lo, uint32_t hi) {
        const uint32_t m = hi - lo;
        if (m <= 1) {
            for (uint32_t k = lo; k < hi; ++k)
                result.push_back(k);
            return;
        }
        // aristas de dependencia i->j (i antes que j en el original y
        // conflictan).
        std::vector<std::vector<uint32_t>> succ(m);
        std::vector<uint32_t> indeg(m, 0);
        for (uint32_t x = 0; x < m; ++x)
            for (uint32_t y = x + 1; y < m; ++y)
                if (asm_dep_conflict(sem[lo + x], sem[lo + y])) {
                    succ[x].push_back(y);
                    ++indeg[y];
                }
        // altura = latencia + max altura de sucesores (camino critico).
        std::vector<float> height(m, 0.0f);
        for (int x = static_cast<int>(m) - 1; x >= 0; --x) {
            float h = 0.0f;
            for (uint32_t sIdx : succ[x])
                h = std::max(h, height[sIdx]);
            height[x] = sem[lo + x].latency + h;
        }
        // list scheduling: entre los listos, el de mayor altura (desempate:
        // orden original -> estable).
        std::vector<uint8_t> done(m, 0);
        std::vector<uint32_t> rem = indeg;
        for (uint32_t step = 0; step < m; ++step) {
            int pick = -1;
            for (uint32_t x = 0; x < m; ++x) {
                if (done[x] || rem[x] != 0) continue;
                if (pick < 0 || height[x] > height[pick] + 1e-6f)
                    pick = static_cast<int>(x);
            }
            done[pick] = 1;
            result.push_back(lo + static_cast<uint32_t>(pick));
            for (uint32_t sIdx : succ[pick])
                --rem[sIdx];
        }
    };
    for (uint32_t k = 0; k < n; ++k) {
        if (sem[k].barrier) {
            sched_segment(seg_start, k);
            result.push_back(k); // la barrera se queda en su sitio
            seg_start = k + 1;
        }
    }
    sched_segment(seg_start, n);

    out.order = result;
    out.moved = false;
    for (uint32_t k = 0; k < n; ++k)
        if (out.order[k] != k) {
            out.moved = true;
            break;
        }
    // INVARIANTE de seguridad: ningun par en conflicto queda invertido.
    std::vector<uint32_t> pos(n);
    for (uint32_t k = 0; k < n; ++k)
        pos[out.order[k]] = k;
    for (uint32_t x = 0; x < n && out.valid; ++x)
        for (uint32_t y = x + 1; y < n; ++y)
            if (asm_dep_conflict(sem[x], sem[y]) && pos[x] > pos[y]) {
                out.valid = false;
                break;
            }
    return out;
}

namespace {
/// ¿La linea es (o empieza por) una etiqueta `nombre:`?
bool line_has_label(const std::string &line) {
    std::string s = line;
    size_t cm = s.find(';');
    if (cm != std::string::npos) s.resize(cm);
    size_t sl = s.find("//");
    if (sl != std::string::npos) s.resize(sl);
    trim(s);
    if (s.empty()) return false;
    size_t k = 0;
    if (!(std::isalpha((unsigned char)s[0]) || s[0] == '_' || s[0] == '.'))
        return false;
    while (k < s.size() &&
           (std::isalnum((unsigned char)s[k]) || s[k] == '_' || s[k] == '.'))
        ++k;
    while (k < s.size() && std::isspace((unsigned char)s[k]))
        ++k;
    return k < s.size() && s[k] == ':';
}
} // namespace

std::string reschedule_asm(Isa isa, const std::string &body, uint32_t ua_id) {
    // Recolecta las lineas de INSTRUCCION (texto original) en el mismo orden
    // que el scheduler; si aparece una etiqueta -> NO se reordena
    // (conservador).
    std::vector<std::string> insns;
    size_t i = 0;
    while (i <= body.size()) {
        size_t nl = body.find('\n', i);
        std::string line = body.substr(
            i, nl == std::string::npos ? std::string::npos : nl - i);
        i = (nl == std::string::npos) ? body.size() + 1 : nl + 1;
        if (line_has_label(line)) return body; // label -> no tocar
        std::string mnem;
        std::vector<std::string> toks;
        if (split_asm_line(line, mnem, toks)) insns.push_back(line);
    }
    if (insns.size() < 2) return body;

    AsmSchedule sc = schedule_asm_block(isa, body, ua_id);
    if (!sc.valid || !sc.moved || sc.order.size() != insns.size())
        return body; // no seguro / no mejora -> original

    std::string out;
    for (size_t k = 0; k < sc.order.size(); ++k) {
        // recorta espacios de cabecera para reindentar uniforme.
        std::string t = insns[sc.order[k]];
        trim(t);
        out += t;
        out += '\n';
    }
    return out;
}

} // namespace instr_db
} // namespace vx
