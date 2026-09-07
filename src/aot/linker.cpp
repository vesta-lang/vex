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
 * @file aot/linker.cpp
 * @brief  AOT.5 -- linker propio: fusiona objetos ELF64 .o en un EXEC.
 *
 * Parsea cada ELF64 @c ET_REL a mano (lectores little-endian propios -- NO
 * incluye LibPEparse para respetar la frontera C/C++ del proyecto; el shim .c
 * sigue siendo el unico que toca la lib).  Fusiona las secciones ALLOC por
 * nombre, construye una tabla de simbolos global, resuelve cada reloc del .o
 * a una @c aot::AbsReloc y emite el ejecutable via @c aot::ObjectWriter (que
 * reutiliza su motor de relocs tras el layout).
 */

#include "aot/linker.h"

#include "aot/aot_native.h"  // aot_make_start_stub, AotArch
#include "aot/ar_archive.h"  //  AOT.5: lector de archivos estaticos .a
#include "aot/link_script.h" //  AOT.5: link-script Vesta (configurable)

#include <cstdint>
#include <cstdio>  // std::snprintf (cabeceras ar)
#include <cstdlib> // std::getenv (ruta de las DLLs del sistema)
#include <cstring> // std::memset/memcpy (cabeceras ar)
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace aot {
namespace {

// ---- Lectores little-endian sobre el buffer del .o ----
inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
inline uint64_t rd64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

// ---- Constantes ELF64 (subset que usamos) ----
constexpr uint16_t ET_REL = 1;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_REL = 9; // i386 (ELF32): relocs sin addend en registro
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint64_t SHF_WRITE = 0x1;
constexpr uint64_t SHF_ALLOC = 0x2;
constexpr uint64_t SHF_EXECINSTR = 0x4;
constexpr uint64_t SHF_TLS = 0x400; // seccion de almacenamiento thread-local
constexpr uint16_t SHN_UNDEF = 0;
constexpr uint8_t STB_GLOBAL = 1;
constexpr uint8_t STT_SECTION = 3;
// Tipos de reloc x86-64.
constexpr uint32_t R_X86_64_64 = 1;
constexpr uint32_t R_X86_64_PC32 = 2;
constexpr uint32_t R_X86_64_GOTPCREL = 9;
constexpr uint32_t R_X86_64_PLT32 = 4;
constexpr uint32_t R_X86_64_32 = 10;
constexpr uint32_t R_X86_64_32S = 11;
constexpr uint32_t R_X86_64_GOTPCRELX = 41;
constexpr uint32_t R_X86_64_REX_GOTPCRELX = 42;

struct ObjSec {
    std::string name;
    uint32_t sh_type = 0;
    uint64_t sh_flags = 0;
    uint64_t sh_size = 0;
    uint64_t sh_offset = 0;
    uint64_t sh_addralign = 0;
    uint32_t sh_info = 0; // SHT_RELA: seccion a la que aplica
    bool comdat = false;  // COFF IMAGE_SCN_LNK_COMDAT (seccion "pick-any")
};
struct ObjSym {
    std::string name;
    uint8_t type = 0;
    uint8_t bind = 0;
    uint16_t shndx = 0;
    uint64_t value = 0;
    bool comdat = false; // simbolo COMDAT/weak (duplicado tolerado: 1o gana)
};
struct ObjRel {
    uint32_t applies_sh = 0; // seccion a la que aplica (indice interno)
    uint64_t off = 0;        // offset del campo dentro de esa seccion
    uint32_t sym = 0;        // indice en la tabla de simbolos
    aot::RelocKind kind = aot::RelocKind::REL32; // normalizado por el parser
    int64_t addend = 0;  // addend FINAL (ELF: del registro +4 si PC32;
                         //   COFF: leido del propio campo)
    bool got = false;    // GOTPCREL: el sitio referencia la entrada GOT
                         //   del simbolo (su DIRECCION), no el simbolo
    bool tls = false;    // TPOFF (local-exec): el sitio recibe el offset
                         //   TLS del simbolo desde el thread pointer
    bool tls_ie = false; // GOTTPOFF (initial-exec): entrada GOT con el
                         //   TPOFF; el sitio REL32 a esa entrada
    bool tls_gd = false; // TLSGD (general-dynamic): se relaja a
                         //   local-exec (secuencia de 16 bytes)
};
struct ParsedObj {
    std::string path;
    std::vector<uint8_t> bytes;
    std::vector<ObjSec> secs; // indexado por indice de seccion
    std::vector<ObjSym> syms; // indexado por indice de symtab
    std::vector<ObjRel> rels;
    bool is32 = false; // ELF32 / COFF i386
};

bool read_file(const std::string &path, std::vector<uint8_t> &out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize n = f.tellg();
    if (n < 0) return false;
    f.seekg(0);
    out.resize((size_t)n);
    if (n > 0) f.read(reinterpret_cast<char *>(out.data()), n);
    return (bool)f;
}

// Carga los bytes de un miembro de archivo: en un .a normal son un slice del
// buffer; en un thin archive estan en un fichero externo (la ruta es el nombre,
// relativa -> respecto al directorio del .a).
bool load_ar_member_bytes(const std::string &archive_path,
                          const std::vector<uint8_t> &abuf, const ArMember &m,
                          std::vector<uint8_t> &out) {
    if (m.is_thin) {
        std::string p = m.name;
        const bool absolute = !p.empty() && (p[0] == '/' || p[0] == '\\' ||
                                             (p.size() > 1 && p[1] == ':'));
        if (!absolute) {
            const size_t sl = archive_path.find_last_of("\\/");
            if (sl != std::string::npos) p = archive_path.substr(0, sl + 1) + p;
        }
        return read_file(p, out);
    }
    out.assign(abuf.begin() + m.data_offset,
               abuf.begin() + m.data_offset + m.size);
    return true;
}

bool parse_elf_obj(const std::string &path, ParsedObj &po, std::string &err) {
    po.path = path;
    // Si los bytes ya estan cargados (miembro de un archivo .a en memoria) no
    // se vuelve a leer del disco.
    if (po.bytes.empty() && !read_file(path, po.bytes)) {
        err = "no se puede abrir el objeto: " + path;
        return false;
    }
    const std::vector<uint8_t> &b = po.bytes;
    if (b.size() < 64 || b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' ||
        b[3] != 'F') {
        err = path + ": no es un ELF";
        return false;
    }
    if (b[4] != 2) { // ELFCLASS64
        err = path + ": no es ELF64 (slice 1 solo enlaza ELF64)";
        return false;
    }
    const uint16_t e_type = rd16(&b[16]);
    if (e_type != ET_REL) {
        err = path + ": no es un objeto relocatable (ET_REL)";
        return false;
    }
    const uint64_t e_shoff = rd64(&b[40]);
    const uint16_t e_shentsize = rd16(&b[58]);
    const uint16_t e_shnum = rd16(&b[60]);
    const uint16_t e_shstrndx = rd16(&b[62]);
    if (e_shoff == 0 || e_shnum == 0 ||
        e_shoff + (uint64_t)e_shnum * e_shentsize > b.size()) {
        err = path + ": tabla de secciones invalida";
        return false;
    }
    // Cabeceras de seccion (sin nombre todavia).
    po.secs.resize(e_shnum);
    for (uint16_t i = 0; i < e_shnum; ++i) {
        const uint8_t *sh = &b[e_shoff + (uint64_t)i * e_shentsize];
        ObjSec &s = po.secs[i];
        s.sh_type = rd32(sh + 4);
        s.sh_flags = rd64(sh + 8);
        s.sh_offset = rd64(sh + 24);
        s.sh_size = rd64(sh + 32);
        s.sh_info = rd32(sh + 44);
        s.sh_addralign = rd64(sh + 48);
        // sh_name lo resolvemos tras conocer la shstrtab.
        s.name.assign(reinterpret_cast<const char *>(sh)); // placeholder
        s.name.clear();
        s.name = std::to_string(rd32(sh)); // guarda sh_name como string temp
    }
    // Resolver nombres via shstrtab.
    if (e_shstrndx >= e_shnum) {
        err = path + ": shstrndx invalido";
        return false;
    }
    const ObjSec &shstr = po.secs[e_shstrndx];
    auto str_at = [&](uint64_t base, uint32_t off) -> std::string {
        uint64_t p = base + off;
        std::string r;
        while (p < b.size() && b[p] != 0)
            r.push_back((char)b[p++]);
        return r;
    };
    for (uint16_t i = 0; i < e_shnum; ++i) {
        const uint8_t *sh = &b[e_shoff + (uint64_t)i * e_shentsize];
        po.secs[i].name = str_at(shstr.sh_offset, rd32(sh));
    }
    // Symtab + strtab.
    int symtab_idx = -1;
    for (uint16_t i = 0; i < e_shnum; ++i)
        if (po.secs[i].sh_type == SHT_SYMTAB) {
            symtab_idx = i;
            break;
        }
    if (symtab_idx >= 0) {
        const uint8_t *shp = &b[e_shoff + (uint64_t)symtab_idx * e_shentsize];
        const uint32_t strtab_idx = rd32(shp + 40); // sh_link
        const ObjSec &st = po.secs[symtab_idx];
        const ObjSec &strs =
            (strtab_idx < e_shnum) ? po.secs[strtab_idx] : po.secs[0];
        const uint64_t nsyms = st.sh_size / 24;
        po.syms.resize(nsyms);
        for (uint64_t k = 0; k < nsyms; ++k) {
            const uint8_t *sy = &b[st.sh_offset + k * 24];
            ObjSym &os = po.syms[k];
            os.name = str_at(strs.sh_offset, rd32(sy));
            const uint8_t info = sy[4];
            os.type = info & 0xf;
            os.bind = info >> 4;
            os.shndx = rd16(sy + 6);
            os.value = rd64(sy + 8);
        }
    }
    // Relocs (SHT_RELA).  Normalizamos el tipo ELF a aot::RelocKind + addend
    // FINAL aqui (el addend ELF vive en el registro; PC32/PLT32 llevan +4 para
    // igualar el REL32 del writer: writer = target-(site+4)+addend, ELF
    // PC32 = S+A-P -> addend+=4).
    for (uint16_t i = 0; i < e_shnum; ++i) {
        const ObjSec &rs = po.secs[i];
        if (rs.sh_type != SHT_RELA) continue;
        const uint64_t nrel = rs.sh_size / 24;
        for (uint64_t k = 0; k < nrel; ++k) {
            const uint8_t *re = &b[rs.sh_offset + k * 24];
            ObjRel r;
            r.applies_sh = rs.sh_info;
            r.off = rd64(re);
            const uint64_t info = rd64(re + 8);
            r.sym = (uint32_t)(info >> 32);
            const uint32_t rt = (uint32_t)(info & 0xffffffff);
            const int64_t ad = (int64_t)rd64(re + 16);
            switch (rt) {
            case R_X86_64_PC32:
            case R_X86_64_PLT32:
                r.kind = aot::RelocKind::REL32;
                r.addend = ad + 4;
                break;
            case R_X86_64_GOTPCREL:
            case R_X86_64_GOTPCRELX:
            case R_X86_64_REX_GOTPCRELX:
                // El sitio (disp32) carga la DIRECCION del simbolo desde su
                // entrada GOT.  Mismo encaje PC-relativo que PC32 (addend+=4)
                // pero el target es la entrada GOT (ver got=true abajo).
                r.kind = aot::RelocKind::REL32;
                r.addend = ad + 4;
                r.got = true;
                break;
            case 23: /* TPOFF32 (local-exec): IMM32 = offset desde el TP */
                r.kind = aot::RelocKind::IMM32;
                r.addend = ad;
                r.tls = true;
                break;
            case 18: /* TPOFF64 (local-exec): IMM64 */
                r.kind = aot::RelocKind::IMM64;
                r.addend = ad;
                r.tls = true;
                break;
            case 22: /* GOTTPOFF (initial-exec): entrada GOT con el TPOFF */
                r.kind = aot::RelocKind::REL32;
                r.addend = ad + 4; // PC-relativo al slot GOT
                r.tls_ie = true;
                break;
            case 19: /* TLSGD (general-dynamic): se relaja a local-exec */
                r.kind = aot::RelocKind::REL32;
                r.addend = 0; // el -4 del reloc es rip-relativo del lea, no TLS
                r.tls_gd = true;
                break;
            case 16: /* DTPMOD64  */
            case 17: /* DTPOFF64  */
            case 20: /* TLSLD     */
            case 21: /* DTPOFF32  */
                // TLS local-dynamic / dtpoff: requieren __tls_get_addr con un
                // modulo y no aparecen en accesos a thread_local de un
                // ejecutable (que usan LE/IE/GD).  Error claro.
                err = path + ": modelo TLS no soportado (reloc " +
                      std::to_string(rt) +
                      "); compila con -ftls-model=local-exec/initial-exec o "
                      "enlazalo con gcc/ld";
                return false;
            case R_X86_64_64:
                r.kind = aot::RelocKind::ABS64;
                r.addend = ad;
                break;
            case R_X86_64_32:
            case R_X86_64_32S:
                r.kind = aot::RelocKind::IMM32;
                r.addend = ad;
                break;
            default:
                err = path + ": tipo de reloc ELF no soportado (" +
                      std::to_string(rt) + ")";
                return false;
            }
            po.rels.push_back(r);
        }
    }
    return true;
}

// Tipos de reloc i386 (ELF32).
constexpr uint32_t R_386_32 = 1;    // abs32: S + A
constexpr uint32_t R_386_PC32 = 2;  // pc-rel: S + A - P
constexpr uint32_t R_386_PLT32 = 4; // pc-rel via PLT: igual encaje que PC32

// Parsea un .o ELF32 (i386).  El i386 usa SHT_REL (8 bytes, addend EN el
// campo, como COFF).  Rellena el MISMO ParsedObj (kind+addend normalizados).
bool parse_elf32_obj(const std::string &path, ParsedObj &po, std::string &err) {
    po.path = path;
    po.is32 = true;
    if (po.bytes.empty() && !read_file(path, po.bytes)) {
        err = "no se puede abrir el objeto: " + path;
        return false;
    }
    const std::vector<uint8_t> &b = po.bytes;
    if (b.size() < 52) {
        err = path + ": ELF32 truncado";
        return false;
    }
    if (rd16(&b[16]) != ET_REL) {
        err = path + ": no es un objeto relocatable (ET_REL)";
        return false;
    }
    const uint32_t e_shoff = rd32(&b[32]);
    const uint16_t e_shentsize = rd16(&b[46]);
    const uint16_t e_shnum = rd16(&b[48]);
    const uint16_t e_shstrndx = rd16(&b[50]);
    if (e_shoff == 0 || e_shnum == 0 ||
        e_shoff + (uint64_t)e_shnum * e_shentsize > b.size()) {
        err = path + ": tabla de secciones ELF32 invalida";
        return false;
    }
    po.secs.resize(e_shnum);
    for (uint16_t i = 0; i < e_shnum; ++i) {
        const uint8_t *sh = &b[e_shoff + (uint64_t)i * e_shentsize];
        ObjSec &s = po.secs[i];
        s.sh_type = rd32(sh + 4);
        s.sh_flags = rd32(sh + 8);
        s.sh_offset = rd32(sh + 16);
        s.sh_size = rd32(sh + 20);
        s.sh_info = rd32(sh + 28);
        s.sh_addralign = rd32(sh + 32);
        s.name = std::to_string(rd32(sh)); // temp (sh_name)
    }
    if (e_shstrndx >= e_shnum) {
        err = path + ": shstrndx invalido";
        return false;
    }
    const ObjSec &shstr = po.secs[e_shstrndx];
    auto str_at = [&](uint64_t base, uint32_t off) -> std::string {
        uint64_t p = base + off;
        std::string r;
        while (p < b.size() && b[p] != 0)
            r.push_back((char)b[p++]);
        return r;
    };
    for (uint16_t i = 0; i < e_shnum; ++i) {
        const uint8_t *sh = &b[e_shoff + (uint64_t)i * e_shentsize];
        po.secs[i].name = str_at(shstr.sh_offset, rd32(sh));
    }
    // Symtab (Elf32_Sym = 16 bytes) + strtab.
    int symtab_idx = -1;
    for (uint16_t i = 0; i < e_shnum; ++i)
        if (po.secs[i].sh_type == SHT_SYMTAB) {
            symtab_idx = i;
            break;
        }
    if (symtab_idx >= 0) {
        const uint8_t *shp = &b[e_shoff + (uint64_t)symtab_idx * e_shentsize];
        const uint32_t strtab_idx = rd32(shp + 24); // sh_link
        const ObjSec &st = po.secs[symtab_idx];
        const ObjSec &strs =
            (strtab_idx < e_shnum) ? po.secs[strtab_idx] : po.secs[0];
        const uint64_t nsyms = st.sh_size / 16;
        po.syms.resize(nsyms);
        for (uint64_t k = 0; k < nsyms; ++k) {
            const uint8_t *sy = &b[st.sh_offset + k * 16];
            ObjSym &os = po.syms[k];
            os.name = str_at(strs.sh_offset, rd32(sy));
            os.value = rd32(sy + 4);
            const uint8_t info = sy[12];
            os.type = info & 0xf;
            os.bind = info >> 4;
            os.shndx = rd16(sy + 14);
        }
    }
    // Relocs: SHT_REL (addend en el campo) y SHT_RELA (addend en el registro).
    for (uint16_t i = 0; i < e_shnum; ++i) {
        const ObjSec &rs = po.secs[i];
        const bool is_rela = (rs.sh_type == SHT_RELA);
        if (rs.sh_type != SHT_REL && !is_rela) continue;
        const uint64_t entsz = is_rela ? 12 : 8;
        const uint64_t nrel = rs.sh_size / entsz;
        const ObjSec *applies =
            (rs.sh_info < e_shnum) ? &po.secs[rs.sh_info] : nullptr;
        for (uint64_t k = 0; k < nrel; ++k) {
            const uint8_t *re = &b[rs.sh_offset + k * entsz];
            ObjRel r;
            r.applies_sh = rs.sh_info;
            r.off = rd32(re);
            const uint32_t info = rd32(re + 4);
            r.sym = info >> 8;
            const uint32_t rt = info & 0xff;
            int64_t A;
            if (is_rela)
                A = (int32_t)rd32(re + 8); // r_addend
            else {
                // addend EN el campo de la seccion a la que aplica.
                A = 0;
                if (applies) {
                    uint64_t f = applies->sh_offset + r.off;
                    if (f + 4 <= b.size()) A = (int32_t)rd32(&b[f]);
                }
            }
            switch (rt) {
            case R_386_PC32:
                r.kind = aot::RelocKind::REL32;
                r.addend = A + 4;
                break;
            case R_386_PLT32: // 4
                r.kind = aot::RelocKind::REL32;
                r.addend = A + 4;
                break;
            case R_386_32:
                r.kind = aot::RelocKind::IMM32;
                r.addend = A;
                break;
            case 17: /* R_386_TLS_LE (local-exec): IMM32 = offset desde el TP.
                        Variante II: TP al final del bloque -> offset negativo,
                        misma formula que x86-64 (sym_block - tls_total). */
                r.kind = aot::RelocKind::IMM32;
                r.addend = A;
                r.tls = true;
                break;
            case 15: /* R_386_TLS_IE       */
            case 16: /* R_386_TLS_GOTIE    */
            case 18: /* R_386_TLS_GD       */
            case 19: /* R_386_TLS_LDM      */
            case 20: /* R_386_TLS_GD_32    */
            case 24: /* R_386_TLS_LDO_32   */
                // initial-exec / general-dynamic en i386 usan GOT-base-relativo
                // y secuencias de relajacion distintas a x86-64.  Para un
                // ejecutable, compila el thread_local en local-exec (sin -fPIC,
                // que es el modelo por defecto) o enlazalo con gcc/ld.
                err = path + ": modelo TLS i386 no soportado (reloc " +
                      std::to_string(rt) +
                      "); compila el thread_local en local-exec (sin -fPIC)";
                return false;
            default:
                err = path + ": tipo de reloc ELF32 no soportado (" +
                      std::to_string(rt) + ")";
                return false;
            }
            po.rels.push_back(r);
        }
    }
    return true;
}

// ---- Constantes COFF (subset) ----
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
constexpr uint16_t IMAGE_FILE_MACHINE_I386 = 0x14c;
constexpr uint16_t IMAGE_REL_I386_DIR32 = 6;  // abs32
constexpr uint16_t IMAGE_REL_I386_REL32 = 20; // pc-rel
constexpr uint32_t IMAGE_SCN_CNT_CODE = 0x20;
constexpr uint32_t IMAGE_SCN_CNT_UNINIT_DATA = 0x80; // .bss
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;
constexpr uint16_t IMAGE_REL_AMD64_ADDR64 = 1;
constexpr uint16_t IMAGE_REL_AMD64_ADDR32 = 2;
constexpr uint16_t IMAGE_REL_AMD64_REL32 = 4;
constexpr int16_t IMAGE_SYM_UNDEFINED = 0;
constexpr uint8_t IMAGE_SYM_CLASS_EXTERNAL = 2;
constexpr uint8_t IMAGE_SYM_CLASS_STATIC = 3;

// Parsea un .obj COFF x86-64 (el de --emit obj --format pe, o de gcc/MSVC).
// Rellena el MISMO ParsedObj que el ELF (kind+addend ya normalizados): el
// addend COFF vive EN el campo -> se lee de los bytes de la seccion.
bool parse_coff_obj(const std::string &path, ParsedObj &po, std::string &err) {
    po.path = path;
    if (po.bytes.empty() && !read_file(path, po.bytes)) {
        err = "no se puede abrir el objeto: " + path;
        return false;
    }
    const std::vector<uint8_t> &b = po.bytes;
    if (b.size() < 20) {
        err = path + ": COFF truncado";
        return false;
    }
    const uint16_t machine = rd16(&b[0]);
    if (machine != IMAGE_FILE_MACHINE_AMD64 &&
        machine != IMAGE_FILE_MACHINE_I386) {
        err = path + ": COFF no es x86-64 ni i386";
        return false;
    }
    po.is32 = (machine == IMAGE_FILE_MACHINE_I386);
    const uint16_t nsec = rd16(&b[2]);
    const uint32_t symtab_off = rd32(&b[8]);
    const uint32_t nsyms = rd32(&b[12]);
    const uint16_t opt_hdr = rd16(&b[16]);
    const uint64_t sh_base = 20 + opt_hdr;
    // String table: justo despues de la symtab (cada simbolo = 18 bytes).
    const uint64_t strtab_off = (uint64_t)symtab_off + (uint64_t)nsyms * 18;
    auto coff_str = [&](uint32_t off) -> std::string {
        uint64_t p = strtab_off + off;
        std::string r;
        while (p < b.size() && b[p] != 0)
            r.push_back((char)b[p++]);
        return r;
    };
    auto sec_name = [&](const uint8_t *sh) -> std::string {
        if (sh[0] == '/') { // "/N" -> offset decimal en la string table
            std::string num((const char *)sh + 1, 7);
            size_t z = num.find('\0');
            if (z != std::string::npos) num.resize(z);
            return coff_str((uint32_t)std::strtoul(num.c_str(), nullptr, 10));
        }
        std::string n;
        for (int i = 0; i < 8 && sh[i]; ++i)
            n.push_back((char)sh[i]);
        return n;
    };
    // Pliega los nombres COMDAT/agrupados de COFF a su seccion base:
    // ".text$mn" -> ".text", ".rdata$zzz" -> ".rdata" (como hace un linker
    // real; ademas evita nombres >8 chars no validos en una imagen PE).
    auto fold_name = [](std::string n) -> std::string {
        size_t d = n.find('$');
        if (d != std::string::npos) n.resize(d);
        return n;
    };
    // Secciones (indice 0 = reservado para alinear con SectionNumber 1-based;
    // usamos secs[1..nsec]).
    po.secs.resize((size_t)nsec + 1);
    for (uint16_t i = 0; i < nsec; ++i) {
        const uint8_t *sh = &b[sh_base + (uint64_t)i * 40];
        ObjSec &s = po.secs[i + 1];
        s.name = fold_name(sec_name(sh));
        s.sh_size = rd32(sh + 16);   // SizeOfRawData
        s.sh_offset = rd32(sh + 20); // PointerToRawData
        const uint32_t chars = rd32(sh + 36);
        // Mapear Characteristics a flags ELF-like que el merge entiende.
        s.sh_flags = SHF_ALLOC;
        if (chars & IMAGE_SCN_MEM_EXECUTE) s.sh_flags |= SHF_EXECINSTR;
        if (chars & IMAGE_SCN_MEM_WRITE) s.sh_flags |= SHF_WRITE;
        s.sh_type = (chars & IMAGE_SCN_CNT_UNINIT_DATA) ? SHT_NOBITS : 1;
        // Alineamiento: bits 20-23 -> 1 << (val-1).
        const uint32_t al = (chars >> 20) & 0xf;
        s.sh_addralign = al ? (1u << (al - 1)) : 1;
        s.sh_info = 0;
        // IMAGE_SCN_LNK_COMDAT (0x1000): seccion "pick-any" (inline/template de
        // C++ duplicado en cada .obj).  El simbolo que la define se tolera
        // duplicado (folding: la primera definicion gana).
        s.comdat = (chars & 0x00001000u) != 0;
        // COFF marca casi todo como cargable; descartamos por nombre las
        // secciones no esenciales para ejecutar: .drectve (directivas del
        // linker), .debug* (info de depuracion) y .pdata/.xdata (tablas SEH de
        // unwinding -- usan relocs ADDR32NB/RVA que no resolvemos y que nuestro
        // propio AOT tampoco emite; sin ellas el binario corre, sin unwinding
        // nativo de excepciones en esos frames).
        // Prefijo (no igualdad): gcc separa codigo frio en .text.unlikely con
        // sus tablas SEH propias .pdata.unlikely / .xdata.unlikely (relocs
        // ADDR32NB/RVA que no resolvemos).  El prefijo las cubre todas.
        if (s.name == ".drectve" || s.name.rfind(".debug", 0) == 0 ||
            s.name.rfind(".pdata", 0) == 0 || s.name.rfind(".xdata", 0) == 0)
            s.sh_flags = 0;
    }
    // Simbolos (18 bytes; saltar aux symbols via NumberOfAuxSymbols).
    po.syms.resize(nsyms);
    for (uint32_t k = 0; k < nsyms;) {
        const uint8_t *sy = &b[symtab_off + (uint64_t)k * 18];
        ObjSym os;
        if (rd32(sy) == 0) // nombre largo: offset en string table @+4
            os.name = coff_str(rd32(sy + 4));
        else {
            for (int i = 0; i < 8 && sy[i]; ++i)
                os.name.push_back((char)sy[i]);
        }
        os.value = rd32(sy + 8);
        const int16_t secnum = (int16_t)rd16(sy + 12);
        const uint8_t sclass = sy[16];
        const uint8_t naux = sy[17];
        // shndx: 0 = UNDEF; >0 = seccion 1-based (coincide con secs[]).
        os.shndx = (secnum <= 0) ? SHN_UNDEF : (uint16_t)secnum;
        os.bind = (sclass == IMAGE_SYM_CLASS_EXTERNAL) ? STB_GLOBAL : 0;
        // Simbolo de SECCION: STATIC con Value 0 cuyo nombre == nombre de
        // seccion (lo que el linker trata como STT_SECTION).
        os.type =
            (sclass == IMAGE_SYM_CLASS_STATIC && secnum > 0 && os.value == 0 &&
             (uint16_t)secnum <= nsec && po.secs[secnum].name == os.name)
                ? STT_SECTION
                : 0;
        // Weak external (105) o simbolo en seccion COMDAT -> duplicado
        // tolerado.
        os.comdat =
            (sclass == 105 /*IMAGE_SYM_CLASS_WEAK_EXTERNAL*/) ||
            (secnum > 0 && (uint16_t)secnum <= nsec && po.secs[secnum].comdat);
        po.syms[k] = os;
        k += 1 + naux; // los aux ocupan slots pero los dejamos vacios
        for (uint8_t a = 0; a < naux && k - 1 + a < nsyms; ++a) {
            // rellenar el slot aux para mantener el indice consistente
        }
    }
    // Relocs por seccion (solo de las secciones que conservamos: las
    // descartadas -- .pdata/.xdata/.debug/.drectve -- tienen sh_flags=0 y sus
    // relocs ADDR32NB/RVA no se procesan).
    for (uint16_t i = 0; i < nsec; ++i) {
        if (!(po.secs[i + 1].sh_flags & SHF_ALLOC)) continue;
        const uint8_t *sh = &b[sh_base + (uint64_t)i * 40];
        const uint32_t prel = rd32(sh + 24); // PointerToRelocations
        const uint16_t nrel = rd16(sh + 32); // NumberOfRelocations
        const uint32_t raw = rd32(sh + 20);  // PointerToRawData
        if (prel == 0 || nrel == 0) continue;
        for (uint16_t k = 0; k < nrel; ++k) {
            const uint8_t *re = &b[prel + (uint64_t)k * 10];
            ObjRel r;
            r.applies_sh = i + 1; // 1-based, coincide con secs[]
            r.off = rd32(re);     // VirtualAddress = offset en la seccion
            r.sym = rd32(re + 4); // SymbolTableIndex
            const uint16_t type = rd16(re + 8);
            // El addend COFF vive EN el campo (a diferencia de ELF RELA).
            const uint64_t field = (uint64_t)raw + r.off;
            switch (type) {
            case IMAGE_REL_AMD64_REL32:
                r.kind = aot::RelocKind::REL32;
                r.addend =
                    (field + 4 <= b.size()) ? (int32_t)rd32(&b[field]) : 0;
                break;
            case IMAGE_REL_AMD64_ADDR64:
                r.kind = aot::RelocKind::ABS64;
                r.addend =
                    (field + 8 <= b.size()) ? (int64_t)rd64(&b[field]) : 0;
                break;
            case IMAGE_REL_AMD64_ADDR32:
            case IMAGE_REL_I386_DIR32:
                r.kind = aot::RelocKind::IMM32;
                r.addend =
                    (field + 4 <= b.size()) ? (int32_t)rd32(&b[field]) : 0;
                break;
            case IMAGE_REL_I386_REL32:
                r.kind = aot::RelocKind::REL32;
                r.addend =
                    (field + 4 <= b.size()) ? (int32_t)rd32(&b[field]) : 0;
                break;
            case 0x0B: // IMAGE_REL_AMD64_SECREL / I386_SECREL (TLS
                       // thread_local): offset del simbolo dentro de su seccion
                       // (.tls).  El addend (offset del var) vive en el campo.
                r.kind = aot::RelocKind::SECREL32;
                r.addend =
                    (field + 4 <= b.size()) ? (int32_t)rd32(&b[field]) : 0;
                break;
            default:
                err = path + ": tipo de reloc COFF no soportado (" +
                      std::to_string(type) + ")";
                return false;
            }
            po.rels.push_back(r);
        }
    }
    return true;
}

// Detecta el formato por magic y despacha al parser correcto.
bool parse_any_obj(const std::string &path, ParsedObj &po, std::string &err) {
    // Autodeteccion por magic.  Si po.bytes ya esta cargado (miembro de un .a)
    // se usa directamente; si no, se leen los primeros bytes del fichero.
    if (po.bytes.empty()) {
        if (!read_file(path, po.bytes)) {
            err = "no se puede abrir el objeto: " + path;
            return false;
        }
    }
    const std::vector<uint8_t> &head = po.bytes;
    if (head.size() < 4) {
        err = path + ": objeto truncado";
        return false;
    }
    if (head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') {
        if (head.size() >= 5 && head[4] == 1) // ELFCLASS32
            return parse_elf32_obj(path, po, err);
        return parse_elf_obj(path, po, err); // ELFCLASS64
    }
    const uint16_t m = rd16(&head[0]);
    if (m == IMAGE_FILE_MACHINE_AMD64 || m == IMAGE_FILE_MACHINE_I386)
        return parse_coff_obj(path, po, err);
    err = path + ": formato de objeto no reconocido (ELF / COFF x86)";
    return false;
}

// Seccion fusionada de salida.
struct MergedSec {
    std::string name;
    uint32_t perms = 0;        // r/w/x compuesto en flags del writer
    std::vector<uint8_t> data; // bytes (PROGBITS)
    uint64_t bss_size = 0;     // cola NOBITS
    uint64_t align = 8;
};

inline uint64_t align_up(uint64_t v, uint64_t a) {
    if (a < 1) a = 1;
    return (v + a - 1) / a * a;
}

// Lee los nombres EXPORTADOS de una libreria del sistema delegando en el shim
// C (PE -> LibPEparse export table; ELF .so -> LibELFparse dynsym).  Asi el
// linker resuelve los imports leyendo lo que la libreria REALMENTE exporta, NO
// una lista de simbolos embebida en el compilador.
bool lib_read_exports(const std::string &path, bool is_pe,
                      std::vector<std::string> &names) {
    char **arr = nullptr;
    int count = 0;
    const int rc = is_pe ? aot_pe_export_names(path.c_str(), &arr, &count)
                         : aot_elf_export_names(path.c_str(), &arr, &count);
    if (rc != 0) return false;
    names.reserve(names.size() + (size_t)count);
    for (int i = 0; i < count; ++i)
        if (arr[i]) names.emplace_back(arr[i]);
    aot_free_pe_export_names(arr, count); // mismo allocator (FreeExportNames64)
    return true;
}

// Ruta de una DLL del sistema en %SystemRoot%\System32 (Windows).
std::string system_dll_path(const char *dll) {
    const char *root = std::getenv("SystemRoot");
    if (!root || !*root) root = "C:\\Windows";
    return std::string(root) + "\\System32\\" + dll;
}

// Localiza libc.so.6 en las rutas estandar.  Con @p sysroot no vacio (cross-
// compile ELF desde otro SO) se buscan bajo esa raiz; si no, en rutas nativas
// (Linux).  Si no se encuentra, el usuario pasa la .so explicitamente.
std::string libc_so_path(const std::string &sysroot, bool is32) {
    static const char *const cands64[] = {"/usr/lib/x86_64-linux-gnu/libc.so.6",
                                          "/lib/x86_64-linux-gnu/libc.so.6",
                                          "/lib64/libc.so.6",
                                          "/usr/lib64/libc.so.6",
                                          "/usr/lib/libc.so.6",
                                          "/lib/libc.so.6"};
    static const char *const cands32[] = {"/usr/lib/i386-linux-gnu/libc.so.6",
                                          "/lib/i386-linux-gnu/libc.so.6",
                                          "/lib32/libc.so.6",
                                          "/usr/lib32/libc.so.6",
                                          "/usr/lib/libc.so.6",
                                          "/lib/libc.so.6"};
    const char *const *cands = is32 ? cands32 : cands64;
    const int ncand = 6;
    for (int ci = 0; ci < ncand; ++ci) {
        const char *p = cands[ci];
        const std::string full =
            sysroot.empty() ? std::string(p) : (sysroot + p);
        std::ifstream f(full, std::ios::binary);
        if (f.good()) return full;
    }
    return std::string();
}

// Basename de una ruta (para el soname / nombre de DLL del descriptor import).
std::string path_basename(const std::string &p) {
    const size_t sl = p.find_last_of("\\/");
    return (sl == std::string::npos) ? p : p.substr(sl + 1);
}

} // namespace

bool aot_link(const std::vector<std::string> &inputs,
              const std::string &out_path, const LinkOptions &opts,
              std::string &err) {
    if (opts.fmt != ObjFormat::ELF && opts.fmt != ObjFormat::PE) {
        err = "linker: solo soporta --format elf o pe";
        return false;
    }
    if (inputs.empty()) {
        err = "linker: sin objetos de entrada";
        return false;
    }
    // 1. Parsear entradas.  Se distinguen OBJETOS (.o/.obj: siempre se enlazan)
    //    de ARCHIVOS estaticos (.a: "pull" perezoso -- solo se extraen los
    //    miembros que definen un simbolo realmente referenciado, semantica
    //    estandar de linker).  Auto-detecta ELF32/64 y COFF i386/AMD64.
    std::vector<ParsedObj> objs;

    // Archivo .a cargado + su indice simbolo->miembro (del indice del .a si lo
    // trae, o construido escaneando los symtab de los miembros como fallback).
    struct ArchiveInput {
        std::string path;
        std::vector<uint8_t> buf;
        std::vector<ArMember> members;
        std::vector<bool> pulled;
        std::unordered_map<std::string, int> sym_to_member;
    };
    std::vector<ArchiveInput> archives;
    // DLLs pasadas como entrada (el usuario puede enlazar contra los exports de
    // cualquier .dll, ademas de las del sistema): se consultan sus exports para
    // resolver imports, igual que kernel32/CRT.
    std::vector<std::string> dll_inputs;

    for (const std::string &in : inputs) {
        std::vector<uint8_t> buf;
        if (!read_file(in, buf)) {
            err = "no se puede abrir la entrada: " + in;
            return false;
        }
        // Libreria compartida (no es un objeto a fusionar; se usa como fuente
        // de imports a partir de sus exports):
        //  - PE/.dll: imagen 'MZ'.
        //  - ELF/.so: ELF cuyo e_type es ET_DYN (3) -- una .o es ET_REL (1).
        if (buf.size() >= 2 && buf[0] == 'M' && buf[1] == 'Z') {
            dll_inputs.push_back(in);
            continue;
        }
        if (buf.size() >= 18 && buf[0] == 0x7f && buf[1] == 'E' &&
            buf[2] == 'L' && buf[3] == 'F' && rd16(&buf[16]) == 3 /*ET_DYN*/) {
            dll_inputs.push_back(in);
            continue;
        }
        if (ar_is_archive(buf)) {
            ArchiveInput a;
            a.path = in;
            a.buf = std::move(buf);
            std::vector<ArSymbol> arsyms;
            if (!ar_parse(a.buf, a.members, arsyms, err)) {
                err = in + ": " + err;
                return false;
            }
            a.pulled.assign(a.members.size(), false);
            if (!arsyms.empty()) {
                // Indice del propio .a (rapido: no parsea miembros no usados).
                for (const ArSymbol &s : arsyms)
                    if (s.member_index >= 0)
                        a.sym_to_member.emplace(s.name, s.member_index);
            } else {
                // Fallback: escanear los globals definidos de cada miembro.
                for (size_t mi = 0; mi < a.members.size(); ++mi) {
                    const ArMember &m = a.members[mi];
                    ParsedObj tmp;
                    if (!load_ar_member_bytes(a.path, a.buf, m, tmp.bytes))
                        continue; // thin: fichero externo ausente
                    std::string e2;
                    if (!parse_any_obj(a.path + "(" + m.name + ")", tmp, e2))
                        continue; // miembro no-objeto: ignorar
                    for (const ObjSym &sy : tmp.syms)
                        if (sy.bind == STB_GLOBAL && sy.shndx != SHN_UNDEF &&
                            sy.type != STT_SECTION && !sy.name.empty())
                            a.sym_to_member.emplace(sy.name, (int)mi);
                }
            }
            archives.push_back(std::move(a));
        } else {
            ParsedObj po;
            po.bytes = std::move(buf); // pre-cargado (no se relee del disco)
            if (!parse_any_obj(in, po, err)) return false;
            objs.push_back(std::move(po));
        }
    }
    if (objs.empty()) {
        err = "linker: sin objetos de entrada (solo se dieron archivos .a)";
        return false;
    }

    // 1.b "Pull" perezoso de miembros de archivo: incluye un miembro solo si
    //     define un simbolo global referenciado-y-aun-no-definido.  Itera a
    //     punto fijo (un miembro nuevo puede referenciar otros).
    {
        std::unordered_set<std::string> defined, referenced;
        auto scan = [&](const ParsedObj &o) {
            for (const ObjSym &sy : o.syms) {
                if (sy.bind != STB_GLOBAL || sy.name.empty() ||
                    sy.type == STT_SECTION)
                    continue;
                if (sy.shndx == SHN_UNDEF)
                    referenced.insert(sy.name);
                else
                    defined.insert(sy.name);
            }
        };
        for (const ParsedObj &o : objs)
            scan(o);
        bool changed = true;
        while (changed) {
            changed = false;
            std::vector<std::string> undef;
            for (const std::string &n : referenced)
                if (!defined.count(n)) undef.push_back(n);
            for (const std::string &name : undef) {
                if (defined.count(name)) continue; // resuelto en este pase
                for (ArchiveInput &a : archives) {
                    auto it = a.sym_to_member.find(name);
                    if (it == a.sym_to_member.end() || it->second < 0 ||
                        a.pulled[it->second])
                        continue;
                    const int mi = it->second;
                    a.pulled[mi] = true;
                    const ArMember &m = a.members[mi];
                    ParsedObj po;
                    if (!load_ar_member_bytes(a.path, a.buf, m, po.bytes)) {
                        err = a.path + ": miembro thin '" + m.name +
                              "' no encontrado";
                        return false;
                    }
                    if (!parse_any_obj(a.path + "(" + m.name + ")", po, err))
                        return false;
                    scan(po);
                    objs.push_back(std::move(po));
                    changed = true;
                    break;
                }
            }
        }
    }

    // Arquitectura: todos los objetos deben coincidir (32 vs 64 bits).
    const bool is32 = objs[0].is32;
    for (size_t i = 1; i < objs.size(); ++i)
        if (objs[i].is32 != is32) {
            err =
                "linker: mezcla de objetos de 32 y 64 bits (" + inputs[i] + ")";
            return false;
        }

    // 2. Fusionar secciones ALLOC por nombre.  map[(obj, shndx)] ->
    //    (indice de seccion fusionada, offset base dentro de ella).
    std::vector<MergedSec> merged;
    std::unordered_map<std::string, int> merged_by_name;
    struct SecMap {
        int mindex = -1;
        uint64_t base = 0;
    };
    std::vector<std::vector<SecMap>> secmap(objs.size());

    for (size_t oi = 0; oi < objs.size(); ++oi) {
        ParsedObj &o = objs[oi];
        secmap[oi].resize(o.secs.size());
        for (size_t si = 0; si < o.secs.size(); ++si) {
            ObjSec &s = o.secs[si];
            if (!(s.sh_flags & SHF_ALLOC)) continue;
            // Las secciones TLS (.tdata/.tbss) NO se fusionan con el resto: van
            // a un bloque TLS aparte (PT_TLS), construido despues.
            if (s.sh_flags & SHF_TLS) continue;
            // Saltar secciones vacias (gcc emite .data/.bss de tamano 0 en cada
            // .o): crear una seccion vacia en la imagen final la invalidaria.
            if (s.sh_size == 0) continue;
            // perms por flags.
            uint32_t perms = SecFlag::READ;
            const bool is_exec = (s.sh_flags & SHF_EXECINSTR) != 0;
            const bool is_write = (s.sh_flags & SHF_WRITE) != 0;
            if (is_exec)
                perms |= SecFlag::EXEC | SecFlag::CODE;
            else if (is_write)
                perms |= SecFlag::WRITE | SecFlag::DATA;
            else
                perms |= SecFlag::DATA;
            const bool is_bss = (s.sh_type == SHT_NOBITS);
            if (is_bss) perms |= SecFlag::BSS;
            int mi;
            auto it = merged_by_name.find(s.name);
            if (it == merged_by_name.end()) {
                mi = (int)merged.size();
                merged_by_name[s.name] = mi;
                MergedSec m;
                m.name = s.name;
                m.perms = perms;
                m.align = is_exec ? 16 : 8;
                merged.push_back(std::move(m));
            } else {
                mi = it->second;
                merged[mi].perms |= perms; // union conservadora
            }
            MergedSec &m = merged[mi];
            uint64_t a = s.sh_addralign ? s.sh_addralign : 1;
            if (a > m.align) m.align = a;
            // Posicion base = tras data + bss actuales, alineada.
            uint64_t cur = m.data.size() + m.bss_size;
            uint64_t base = align_up(cur, a);
            // Rellenar el hueco de alineamiento con ceros en data (si no hay
            // bss intermedio) -- mantiene data contigua antes del bss.
            if (m.bss_size == 0 && base > m.data.size()) m.data.resize(base, 0);
            secmap[oi][si].mindex = mi;
            secmap[oi][si].base = base;
            if (is_bss) {
                m.bss_size = base + s.sh_size - m.data.size();
            } else {
                // Si ya habia bss, no podemos intercalar data limpia; para el
                // slice 1 asumimos PROGBITS antes que NOBITS por nombre.
                if (base < m.data.size()) base = m.data.size();
                m.data.resize(base, 0);
                const uint8_t *src = &o.bytes[s.sh_offset];
                m.data.insert(m.data.end(), src, src + s.sh_size);
            }
        }
    }

    // 2.b. Bloque TLS (thread_local, modelo local-exec): se combinan las
    //      secciones .tdata (PROGBITS) + .tbss (NOBITS) de todos los objetos en
    //      UN bloque; cada simbolo TLS recibe un offset dentro del bloque.  El
    //      TPOFF de cada acceso = offset_del_simbolo - round_up(total, align)
    //      (el bloque vive BAJO el thread pointer; offsets negativos).
    std::vector<std::vector<int64_t>> tls_off(objs.size());
    std::vector<uint8_t> tls_tdata;
    uint64_t tls_bss = 0;
    uint64_t tls_align = 1;
    bool has_tls = false;
    for (size_t oi = 0; oi < objs.size(); ++oi)
        tls_off[oi].assign(objs[oi].secs.size(), -1);
    // Pase 1: TLS PROGBITS (.tdata) -> bytes contiguos en el bloque.
    for (size_t oi = 0; oi < objs.size(); ++oi) {
        ParsedObj &o = objs[oi];
        for (size_t si = 0; si < o.secs.size(); ++si) {
            ObjSec &s = o.secs[si];
            if (!(s.sh_flags & SHF_TLS) || s.sh_type == SHT_NOBITS ||
                s.sh_size == 0)
                continue;
            has_tls = true;
            const uint64_t a = s.sh_addralign ? s.sh_addralign : 1;
            if (a > tls_align) tls_align = a;
            const uint64_t base = align_up(tls_tdata.size(), a);
            tls_tdata.resize(base, 0);
            const uint8_t *src = &o.bytes[s.sh_offset];
            tls_tdata.insert(tls_tdata.end(), src, src + s.sh_size);
            tls_off[oi][si] = (int64_t)base;
        }
    }
    // Pase 2: TLS NOBITS (.tbss) -> solo tamano, tras el .tdata.
    uint64_t tbss_cursor = tls_tdata.size();
    for (size_t oi = 0; oi < objs.size(); ++oi) {
        ParsedObj &o = objs[oi];
        for (size_t si = 0; si < o.secs.size(); ++si) {
            ObjSec &s = o.secs[si];
            if (!(s.sh_flags & SHF_TLS) || s.sh_type != SHT_NOBITS ||
                s.sh_size == 0)
                continue;
            has_tls = true;
            const uint64_t a = s.sh_addralign ? s.sh_addralign : 1;
            if (a > tls_align) tls_align = a;
            tbss_cursor = align_up(tbss_cursor, a);
            tls_off[oi][si] = (int64_t)tbss_cursor;
            tbss_cursor += s.sh_size;
        }
    }
    tls_bss = tbss_cursor - tls_tdata.size();
    const uint64_t tls_aligned_total =
        align_up(tls_tdata.size() + tls_bss, tls_align);

    // 2.c. Pre-pase TLS local-exec: escribir el TPOFF DIRECTAMENTE en el sitio
    //      (valor constante, no depende de la VA de carga).  Cubre:
    //      - TPOFF32/64 (LE puro): IMM en el sitio.
    //      - TLSGD (general-dynamic): se RELAJA a local-exec reescribiendo la
    //        secuencia de 16 bytes `lea x@tlsgd; call __tls_get_addr` por
    //        `mov %fs:0,%rax; lea x@tpoff(%rax),%rax`.
    for (size_t oi = 0; oi < objs.size(); ++oi) {
        ParsedObj &o = objs[oi];
        for (ObjRel &r : o.rels) {
            if (!r.tls && !r.tls_gd) continue;
            if (r.applies_sh >= secmap[oi].size()) continue;
            const SecMap &site = secmap[oi][r.applies_sh];
            if (site.mindex < 0) continue;
            if (r.sym >= o.syms.size()) continue;
            ObjSym &sy = o.syms[r.sym];
            if (sy.shndx >= tls_off[oi].size() || tls_off[oi][sy.shndx] < 0) {
                err = o.path + ": reloc TLS sobre un simbolo no-TLS";
                return false;
            }
            const int64_t sym_tls = tls_off[oi][sy.shndx] + (int64_t)sy.value;
            const int64_t tpoff =
                sym_tls + r.addend - (int64_t)tls_aligned_total;
            std::vector<uint8_t> &dat = merged[site.mindex].data;
            const uint64_t at = site.base + r.off;
            if (r.tls_gd) {
                // La secuencia GD empieza 4 bytes antes del disp32 del lea.
                if (at < 4 || at + 12 > dat.size()) continue;
                const uint64_t s = at - 4;
                // mov %fs:0, %rax
                static const uint8_t le[9] = {0x64, 0x48, 0x8b, 0x04, 0x25,
                                              0x00, 0x00, 0x00, 0x00};
                for (int b = 0; b < 9; ++b)
                    dat[s + b] = le[b];
                // lea <TPOFF32>(%rax), %rax
                dat[s + 9] = 0x48;
                dat[s + 10] = 0x8d;
                dat[s + 11] = 0x80;
                const uint32_t v = (uint32_t)(int32_t)tpoff;
                for (int b = 0; b < 4; ++b)
                    dat[s + 12 + b] = (uint8_t)(v >> (8 * b));
            } else if (r.kind == aot::RelocKind::IMM64) {
                if (at + 8 <= dat.size()) {
                    const uint64_t v = (uint64_t)tpoff;
                    for (int b = 0; b < 8; ++b)
                        dat[at + b] = (uint8_t)(v >> (8 * b));
                }
            } else { // IMM32 (TPOFF32 local-exec)
                if (at + 4 <= dat.size()) {
                    const uint32_t v = (uint32_t)(int32_t)tpoff;
                    for (int b = 0; b < 4; ++b)
                        dat[at + b] = (uint8_t)(v >> (8 * b));
                }
            }
        }
    }

    // 2.5. Link-script Vesta (configurable por el usuario): ejecuta fn link()
    //      con los builtins de configuracion.  Da los tamanos de seccion ya
    //      fusionados a section_size().  Lo que fije (base/entry/stack) se
    //      aplica abajo; los CLI flags (--link-base/--entry) tienen prioridad.
    std::string eff_entry = opts.entry;
    uint64_t eff_base = opts.image_base;
    uint64_t eff_stack = opts.layout.elf_stack_size;
    std::unordered_map<std::string, uint64_t> script_sections;
    if (!opts.link_script.empty()) {
        std::unordered_map<std::string, uint64_t> sec_sizes;
        for (const MergedSec &m : merged)
            sec_sizes[m.name] = m.data.size() + m.bss_size;
        LinkScriptConfig sc;
        std::string serr;
        if (!aot_run_link_script(opts.link_script, sec_sizes, opts.debug, sc,
                                 serr)) {
            err = serr;
            return false;
        }
        if (eff_entry.empty() && sc.has_entry) eff_entry = sc.entry;
        if (eff_base == 0 && sc.has_base) eff_base = sc.base;
        if (sc.has_stack) eff_stack = sc.stack;
        script_sections = std::move(sc.sections);
    }

    // 3. Indices de seccion en el ObjectWriter.  Hosted (sin entry) reserva
    //    el indice 0 para el stub _start.
    const bool hosted = eff_entry.empty();
    const int sec_base = hosted ? 1 : 0;

    // 4. Tabla de simbolos global: nombre -> (writer-sec, offset).
    struct GDef {
        int wsec = -1;
        uint64_t off = 0;
        bool defined = false;
    };
    std::unordered_map<std::string, GDef> globals;
    // Inits de programa del CPU-dispatch (uno por .o que use el feature).  Se
    // recolectan APARTE (no en globals: cada .o tiene su propio init con su
    // mismo nombre -> no es una definicion multiple) y el linker los ejecuta
    // TODOS antes de main (en orden cpu -> memcpy -> strdisp, porque memcpy/
    // strdisp leen el global de features que cpu_init escribe).  Asi un .o
    // Vesta SIN main (libreria que usa strings/memcpy) tambien inicializa sus
    // slots.
    std::vector<std::pair<int, uint64_t>> init_cpu, init_memcpy, init_strdisp;
    for (size_t oi = 0; oi < objs.size(); ++oi) {
        ParsedObj &o = objs[oi];
        for (ObjSym &sy : o.syms) {
            if (sy.bind != STB_GLOBAL || sy.shndx == SHN_UNDEF ||
                sy.name.empty() || sy.type == STT_SECTION)
                continue;
            if (sy.shndx >= secmap[oi].size()) continue;
            const SecMap &sm = secmap[oi][sy.shndx];
            if (sm.mindex < 0) continue;
            const int wsec = sec_base + sm.mindex;
            const uint64_t off = sm.base + sy.value;
            if (sy.name == "__vx_cpu_init") {
                init_cpu.push_back({wsec, off});
                continue;
            }
            if (sy.name == "__vx_memcpy_init") {
                init_memcpy.push_back({wsec, off});
                continue;
            }
            if (sy.name == "__vx_strdisp_init") {
                init_strdisp.push_back({wsec, off});
                continue;
            }
            GDef d;
            d.wsec = wsec;
            d.off = off;
            d.defined = true;
            auto it = globals.find(sy.name);
            if (it != globals.end() && it->second.defined) {
                // COMDAT / weak: folding -- la primera definicion gana (inline
                // y plantillas de C++ aparecen en multiples .obj del .a).
                if (sy.comdat) continue;
                err =
                    "linker: definicion multiple del simbolo '" + sy.name + "'";
                return false;
            }
            globals[sy.name] = d;
        }
    }

    // 5. Crear el ObjectWriter y anyadir las secciones (stub primero si
    // hosted).
    ObjectWriter w(opts.fmt);
    w.set_mode32(is32); // contenedor ELF32 / PE32 + emisores 32-bit
    LayoutConfig cfg = opts.layout;
    if (eff_base) cfg.image_base = eff_base;
    if (eff_stack) cfg.elf_stack_size = eff_stack;
    w.set_config(cfg);

    const AotArch arch = is32 ? AotArch::X86_32 : AotArch::X86_64;
    StartStub stub;
    if (hosted) {
        stub = aot_make_start_stub(arch, opts.fmt);
        if (!stub.ok) {
            err = "linker: no se pudo sintetizar _start: " + stub.err;
            return false;
        }
        WriterSection ss;
        ss.name = ".text._start";
        ss.flags = SecFlag::READ | SecFlag::EXEC | SecFlag::CODE;
        ss.data = stub.bytes;
        ss.align = 16;
        w.add_section(std::move(ss)); // indice 0
    }
    for (MergedSec &m : merged) {
        WriterSection ws;
        ws.name = m.name;
        ws.flags = m.perms;
        ws.data = std::move(m.data);
        ws.bss_size = (uint32_t)m.bss_size;
        ws.align = m.align;
        // VA fija si el link-script la coloco con place_section(name, addr).
        auto pit = script_sections.find(m.name);
        if (pit != script_sections.end()) ws.vaddr = pit->second;
        w.add_section(std::move(ws));
    }

    // 5.b. Seccion TLS (.tdata + .tbss combinadas) -> el emisor la describe con
    //      un PT_TLS.  data = plantilla .tdata (en fichero), bss_size = .tbss.
    if (has_tls) {
        WriterSection ts;
        ts.name = ".tdata";
        ts.flags =
            SecFlag::READ | SecFlag::WRITE | SecFlag::DATA | SecFlag::TLS;
        ts.data = std::move(tls_tdata);
        ts.bss_size = (uint32_t)tls_bss;
        ts.align = tls_align;
        w.add_section(std::move(ts));
    }

    // 6. Resolver relocs -> AbsReloc del writer.
    // Los simbolos UNDEF que no define ningun objeto/miembro son IMPORTS de
    // libreria del sistema (libc / Win32).  Se resuelven via un thunk `FF 25`
    // por simbolo (mismo patron que la ruta inline) que el emisor materializa
    // como IAT (PE) o GOT dinamico (ELF, DT_NEEDED).  Solo en ejecutables
    // hosted; un kernel (--entry) no auto-importa.
    const bool can_import = hosted;
    const bool fmt_pe = (opts.fmt == ObjFormat::PE);
    struct ImpSite {
        int site_sec;
        uint64_t site_off;
        aot::RelocKind kind;
        int64_t addend;
        std::string sym;
    };
    std::vector<ImpSite> imp_sites;
    std::vector<std::string> unresolved;

    // Mapa simbolo -> DLL leido de los EXPORTS REALES de las DLLs candidatas
    // (NO una lista de simbolos embebida).  Candidatas: el CRT + kernel32 del
    // sistema (busqueda de librerias por defecto, como el implicito -lkernel32
    // -lmsvcrt de un linker), mas cualquier .dll que el usuario pase como
    // entrada.  Un simbolo que NINGUNA DLL exporta no es un import -> error.
    std::unordered_map<std::string, std::string> sym2dll;
    if (can_import) {
        std::vector<std::string> cand;
        if (fmt_pe) {
            // Windows: el CRT + kernel32 del sistema, mas ntdll.
            //
            // `ntdll` esta porque nuestro propio codigo BAJA a la capa NT a
            // proposito -- el asignador reserva con `NtAllocateVirtualMemory`
            // en vez de `VirtualAlloc`, que es esa misma llamada con Win32 por
            // encima --.  Sin ella en las candidatas, un binario AOT que use
            // `gc<T>` no enlazaba: el archivo del GC pedia cinco simbolos `Nt*`
            // que ninguna DLL de la lista exporta.  Y no es una excepcion
            // nuestra: ntdll esta cargada en TODO proceso de Windows antes que
            // kernel32, que de hecho la usa por debajo.
            for (const char *d :
                 {"kernel32.dll", "ntdll.dll", "ucrtbase.dll", "msvcrt.dll"})
                cand.push_back(system_dll_path(d));
        } else {
            // Linux: libc.so.6 (busqueda por defecto, como el -lc implicito;
            // bajo --sysroot si se cross-compila desde otro SO; rutas i386 si
            // el objeto es de 32-bit).
            const std::string libc = libc_so_path(opts.sysroot, is32);
            if (!libc.empty()) cand.push_back(libc);
        }
        for (const std::string &dp :
             dll_inputs) // .dll/.so pasados como entrada
            cand.push_back(dp);
        for (const std::string &dp : cand) {
            std::vector<std::string> exps;
            if (!lib_read_exports(dp, fmt_pe, exps)) continue;
            std::string base = dp;
            const size_t sl = base.find_last_of("\\/");
            if (sl != std::string::npos) base = base.substr(sl + 1);
            for (std::string &e : exps)
                sym2dll.emplace(std::move(e),
                                base); // 1a DLL que lo exporta gana
        }
    }
    // Resuelve el nombre real de un simbolo a su DLL (strip __imp_ de los
    // dllimport de MinGW).  Devuelve "" si ninguna DLL candidata lo exporta.
    /**
     * @brief Es @p n el simbolo de la BASE DE LA IMAGEN?
     *
     * `__ImageBase` no lo define ningun fichero fuente: lo publica el
     * ENLAZADOR, y su direccion es el primer byte de la imagen cargada -- la
     * cabecera `MZ` --.  `link.exe` y `ld` lo sintetizan, y el codigo lo usa
     * como forma barata de saber donde esta cargado su modulo sin llamar a
     * `GetModuleHandle`; el simbolizador lo necesita para restarselo a una
     * direccion y quedarse con el desplazamiento dentro del modulo.
     *
     * Aqui faltaba, y el modo de fallar era el peor posible: no lo define
     * ningun objeto y no lo exporta ninguna DLL, asi que salia como "simbolo no
     * resuelto" a muchas capas del sitio donde se referenciaba.  Con un archivo
     * `.a` por medio ni siquiera hacia falta usar la funcion que lo menciona:
     * la unidad de enlace es el OBJETO entero, asi que traerse `os_alloc` se
     * traia tambien esta referencia.
     *
     * Se aceptan los tres nombres que usan las herramientas: el de PE con y sin
     * subrayado de mas (i386 decora con `_`), y el equivalente de ELF.
     */
    auto es_base_de_imagen = [](const std::string &n) {
        return n == "__ImageBase" || n == "___ImageBase" ||
               n == "__executable_start";
    };

    auto dll_of = [&sym2dll](const std::string &n) -> std::string {
        const std::string real = (n.rfind("__imp_", 0) == 0) ? n.substr(6) : n;
        auto it = sym2dll.find(real);
        return it != sym2dll.end() ? it->second : std::string();
    };

    // GOT (GOTPCREL): cada sitio carga la DIRECCION de un simbolo desde su
    // entrada GOT.  Se recolectan aqui y se construye una seccion .got tras los
    // thunks: cada entrada (8B) se rellena con la direccion del simbolo
    //   - definido en la imagen -> ABS64 al simbolo (el emisor PIE lo convierte
    //     en R_X86_64_RELATIVE), o
    //   - import del sistema -> ABS64 al thunk (puntero de funcion llamable),
    // y el sitio se resuelve REL32 a la entrada GOT.
    struct GotSite {
        int site_sec;
        uint64_t site_off;
        int64_t addend;
        std::string key; // identifica la entrada GOT (dedup)
    };
    std::vector<GotSite> got_sites;
    struct GotEntry {
        bool is_ext = false;
        int def_wsec = 0;
        uint64_t def_off = 0;
        std::string ext_name;
        bool is_tls_const = false; // entrada IE: contiene un TPOFF constante
        /* La entrada vale la BASE DE LA IMAGEN.  Un acceso a `__ImageBase` por
         * GOT no lo emite hoy nuestro backend, pero SI otro compilador -- es
         * lo normal en codigo independiente de posicion --, y sin esto ese
         * objeto no enlaza.  Compatibilidad, no una via nuestra. */
        bool is_imagebase = false;
        int64_t tls_const = 0;
    };
    std::unordered_map<std::string, GotEntry> got_entries;
    std::unordered_set<std::string>
        got_ext_syms; // externals que necesitan thunk

    for (size_t oi = 0; oi < objs.size(); ++oi) {
        ParsedObj &o = objs[oi];
        for (ObjRel &r : o.rels) {
            // TLS local-exec (r.tls) y general-dynamic relajado (r.tls_gd) ya
            // se parchearon en el pre-pase 2.c (valor TP-relativo constante).
            if (r.tls || r.tls_gd) continue;
            if (r.applies_sh >= secmap[oi].size()) continue;
            const SecMap &site = secmap[oi][r.applies_sh];
            if (site.mindex < 0) continue; // reloc en seccion no-ALLOC: ignorar
            const int site_sec = sec_base + site.mindex;
            const uint64_t site_off = site.base + r.off;
            if (r.sym >= o.syms.size()) continue;
            ObjSym &sy = o.syms[r.sym];
            // La llamada a __tls_get_addr de la secuencia GD desaparece tras la
            // relajacion a local-exec; su reloc PLT32 no se materializa.
            if (sy.name == "__tls_get_addr") continue;

            if (r.tls_ie) {
                // GOTTPOFF (initial-exec): el sitio carga el TPOFF desde una
                // entrada GOT que contiene el offset TP-relativo CONSTANTE.
                if (sy.shndx >= tls_off[oi].size() ||
                    tls_off[oi][sy.shndx] < 0) {
                    err = o.path + ": GOTTPOFF sobre un simbolo no-TLS";
                    return false;
                }
                const int64_t sym_tls =
                    tls_off[oi][sy.shndx] + (int64_t)sy.value;
                const int64_t tpoff = sym_tls - (int64_t)tls_aligned_total;
                GotEntry ge;
                ge.is_tls_const = true;
                ge.tls_const = tpoff;
                const std::string key = "Tc" + std::to_string(tpoff);
                got_entries.emplace(key, ge);
                got_sites.push_back({site_sec, site_off, r.addend, key});
                continue;
            }

            if (r.got) {
                // Resolver la DIRECCION del simbolo destino de la entrada GOT.
                GotEntry ge;
                std::string key;
                bool gok = false;
                if (sy.type == STT_SECTION || sy.shndx != SHN_UNDEF) {
                    if (sy.shndx < secmap[oi].size() &&
                        secmap[oi][sy.shndx].mindex >= 0) {
                        const SecMap &tm = secmap[oi][sy.shndx];
                        ge.def_wsec = sec_base + tm.mindex;
                        ge.def_off =
                            tm.base +
                            (sy.type == STT_SECTION ? 0 : (uint64_t)sy.value);
                        key = "D" + std::to_string(ge.def_wsec) + ":" +
                              std::to_string(ge.def_off);
                        gok = true;
                    }
                } else {
                    auto it = globals.find(sy.name);
                    if (it != globals.end() && it->second.defined) {
                        ge.def_wsec = it->second.wsec;
                        ge.def_off = it->second.off;
                        key = "D" + std::to_string(ge.def_wsec) + ":" +
                              std::to_string(ge.def_off);
                        gok = true;
                    } else if (es_base_de_imagen(sy.name)) {
                        /* La misma respuesta que en la ruta directa, por la
                         * misma razon: lo publica el enlazador.  Una sola
                         * entrada para todos los sitios -- la base es una --,
                         * de ahi que la clave sea constante. */
                        ge.is_imagebase = true;
                        key = "B";
                        gok = true;
                    } else if (can_import && !dll_of(sy.name).empty()) {
                        ge.is_ext = true;
                        ge.ext_name = sy.name;
                        key = "E" + sy.name;
                        got_ext_syms.insert(sy.name);
                        gok = true;
                    }
                }
                if (!gok) {
                    unresolved.push_back(sy.name);
                    continue;
                }
                got_entries.emplace(key, ge);
                got_sites.push_back({site_sec, site_off, r.addend, key});
                continue;
            }

            RelocTarget tgt;
            bool ok = false;
            if (sy.type == STT_SECTION) {
                if (sy.shndx < secmap[oi].size() &&
                    secmap[oi][sy.shndx].mindex >= 0) {
                    const SecMap &tm = secmap[oi][sy.shndx];
                    tgt = RelocTarget::addr(sec_base + tm.mindex, tm.base);
                    ok = true;
                }
            } else if (sy.shndx != SHN_UNDEF) {
                if (sy.shndx < secmap[oi].size() &&
                    secmap[oi][sy.shndx].mindex >= 0) {
                    const SecMap &tm = secmap[oi][sy.shndx];
                    tgt = RelocTarget::addr(sec_base + tm.mindex,
                                            tm.base + sy.value);
                    ok = true;
                }
            } else { // UNDEF -> resolver por nombre global
                auto it = globals.find(sy.name);
                if (it != globals.end() && it->second.defined) {
                    tgt = RelocTarget::addr(it->second.wsec, it->second.off);
                    ok = true;
                } else if (es_base_de_imagen(sy.name)) {
                    /* Lo pone EL ENLAZADOR, no un fichero fuente.  Ver
                     * `es_base_de_imagen`. */
                    tgt = RelocTarget::image_base();
                    ok = true;
                } else if (can_import && !dll_of(sy.name).empty()) {
                    // Una DLL candidata EXPORTA este simbolo -> import por IAT
                    // (thunk libc o slot __imp_, resuelto tras el bucle).  Un
                    // simbolo que ninguna DLL exporta NO se auto-importa.
                    imp_sites.push_back(
                        {site_sec, site_off, r.kind, r.addend, sy.name});
                    continue;
                } else {
                    unresolved.push_back(sy.name);
                    continue;
                }
            }
            if (!ok) continue;
            // kind + addend ya fueron normalizados por el parser (ELF: del
            // registro RELA con +4 en PC32; COFF: leidos del propio campo).
            w.add_reloc(site_sec, site_off, tgt, r.kind, r.addend);
        }
    }

    // 6.b Resolver los imports de libreria (PE IAT).  Dos clases:
    //   - Simbolo libc normal (malloc/free/memcpy/abort...): el codigo emitio
    //     `call sym` (E8 rel32).  Como `call sym` apunta a un THUNK `FF 25`
    //     (jmp [rip+IAT]) intra-imagen; el thunk se parchea por el mecanismo de
    //     import (add_import_call) al slot real de la IAT.
    //   - Simbolo `__imp_X` (dllimport de MinGW): el codigo ya hizo
    //     `call [rip+__imp_X]` (FF 15) o `mov reg,[rip+__imp_X]`; el sitio de
    //     la reloc ES el disp32, que debe apuntar al slot de la IAT.  Se
    //     registra como un import directo (call_off = inicio del FF 15 =
    //     site_off-2) sin anyadir reloc.
    if (!imp_sites.empty() || !got_sites.empty()) {
        // El DLL de cada simbolo se LEE de los exports reales (sym2dll), no se
        // adivina con una tabla embebida: dll_of(sym) -> la DLL que lo exporta.
        std::vector<uint8_t> thunk_bytes;
        std::unordered_map<std::string, uint64_t> thunk_off;
        std::vector<ImportCall> calls;

        // Crea (si no existe) un thunk `FF 25` + su import-call para un simbolo
        // externo normal.  El thunk es una funcion llamable (jmp [rip+GOT]).
        auto ensure_thunk = [&](const std::string &sym) {
            if (thunk_off.find(sym) != thunk_off.end()) return;
            const uint64_t off = thunk_bytes.size();
            const uint8_t t[6] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
            thunk_bytes.insert(thunk_bytes.end(), t, t + 6);
            thunk_off[sym] = off;
            calls.push_back({dll_of(sym), sym, -1 /*thunk_sec abajo*/, off});
        };

        for (const ImpSite &s : imp_sites) {
            if (s.sym.rfind("__imp_", 0) == 0) {
                // Slot IAT directo: el FF 15 empieza 2 bytes antes del disp32.
                const std::string func = s.sym.substr(6);
                calls.push_back({dll_of(s.sym), func, s.site_sec,
                                 s.site_off >= 2 ? s.site_off - 2 : 0});
            } else {
                ensure_thunk(s.sym);
            }
        }
        // Externos referenciados SOLO via GOT tambien necesitan un thunk (para
        // tener su direccion como puntero de funcion llamable).
        for (const std::string &sym : got_ext_syms)
            ensure_thunk(sym);

        int thunk_sec = -1;
        if (!thunk_bytes.empty()) {
            WriterSection ts;
            ts.name = ".text.thunks";
            ts.flags = SecFlag::READ | SecFlag::EXEC | SecFlag::CODE;
            ts.data = std::move(thunk_bytes);
            ts.align = 16;
            thunk_sec = w.add_section(std::move(ts));
            // Reapuntar cada `call sym` (rel32) al thunk correspondiente.
            for (const ImpSite &s : imp_sites) {
                if (s.sym.rfind("__imp_", 0) == 0) continue;
                w.add_reloc(s.site_sec, s.site_off,
                            RelocTarget::addr(thunk_sec, thunk_off[s.sym]),
                            s.kind, s.addend);
            }
        }
        for (ImportCall &c : calls) {
            if (c.call_section < 0) c.call_section = thunk_sec;
            w.add_import_call(c);
        }

        // 6.c Construir la seccion .got (una entrada de 8B por simbolo
        // referenciado via GOTPCREL).  Cada entrada se rellena con la direccion
        // del simbolo (ABS64 -> el emisor PIE la materializa como
        // R_X86_64_RELATIVE), y cada sitio GOTPCREL se resuelve REL32 a su
        // entrada.
        if (!got_sites.empty()) {
            std::unordered_map<std::string, uint64_t> got_entry_off;
            std::vector<uint8_t> got_data;
            for (const auto &kv : got_entries) {
                got_entry_off[kv.first] = got_data.size();
                if (kv.second.is_tls_const) {
                    // IE: la entrada GOT lleva el TPOFF constante (sin reloc).
                    const uint64_t v = (uint64_t)kv.second.tls_const;
                    for (int b = 0; b < 8; ++b)
                        got_data.push_back((uint8_t)(v >> (8 * b)));
                } else {
                    got_data.insert(got_data.end(), 8, 0);
                }
            }
            WriterSection gs;
            gs.name = ".got";
            gs.flags = SecFlag::READ | SecFlag::WRITE | SecFlag::DATA;
            gs.data = std::move(got_data);
            gs.align = 8;
            const int got_sec = w.add_section(std::move(gs));
            // Rellenar cada entrada con la direccion de su simbolo.
            for (const auto &kv : got_entries) {
                const GotEntry &ge = kv.second;
                if (ge.is_tls_const) continue; // IE: valor constante, sin reloc
                const uint64_t eoff = got_entry_off[kv.first];
                RelocTarget t;
                if (ge.is_imagebase)
                    t = RelocTarget::image_base();
                else if (ge.is_ext)
                    t = RelocTarget::addr(thunk_sec, thunk_off[ge.ext_name]);
                else
                    t = RelocTarget::addr(ge.def_wsec, ge.def_off);
                w.add_reloc(got_sec, eoff, t, RelocKind::ABS64);
            }
            // Resolver cada sitio GOTPCREL -> REL32 a su entrada GOT.
            for (const GotSite &gsi : got_sites)
                w.add_reloc(gsi.site_sec, gsi.site_off,
                            RelocTarget::addr(got_sec, got_entry_off[gsi.key]),
                            RelocKind::REL32, gsi.addend);
        }
    }

    // 7. Punto de entrada.
    if (hosted) {
        auto it = globals.find("main");
        if (it == globals.end() || !it->second.defined) {
            err = "linker: 'main' no esta definido (usa --entry <sym> para un "
                  "binario sin main, p.ej. un kernel)";
            return false;
        }
        const GDef mn = it->second;
        const bool any_init =
            !init_cpu.empty() || !init_memcpy.empty() || !init_strdisp.empty();
        if (any_init) {
            // Sintetizar __vx_premain: llama a CADA init de programa (en orden
            // cpu -> memcpy -> strdisp) y salta a main.  Asi los slots fp de
            // TODOS los .o (incluidos los .o sin main) quedan inicializados.
            // El init del .o de main ademas corre via su prologo (idempotente).
            std::vector<uint8_t> pm;
            struct PReloc {
                uint64_t off;
                int wsec;
                uint64_t toff;
            };
            std::vector<PReloc> prelocs;
            auto emit_call = [&](const std::pair<int, uint64_t> &t) {
                pm.push_back(0xE8); // call rel32
                for (int k = 0; k < 4; ++k)
                    pm.push_back(0);
                prelocs.push_back({pm.size() - 4, t.first, t.second});
            };
            for (const auto &p : init_cpu)
                emit_call(p);
            for (const auto &p : init_memcpy)
                emit_call(p);
            for (const auto &p : init_strdisp)
                emit_call(p);
            pm.push_back(0xE9); // jmp rel32 -> main (tail)
            for (int k = 0; k < 4; ++k)
                pm.push_back(0);
            prelocs.push_back({pm.size() - 4, mn.wsec, mn.off});

            WriterSection pms;
            pms.name = ".text._premain";
            pms.flags = SecFlag::READ | SecFlag::EXEC | SecFlag::CODE;
            pms.data = std::move(pm);
            pms.align = 16;
            const int premain_sec = w.add_section(std::move(pms));
            for (const PReloc &pr : prelocs)
                w.add_reloc(premain_sec, pr.off,
                            RelocTarget::addr(pr.wsec, pr.toff),
                            RelocKind::REL32);
            w.set_entry(0, 0); // stub en indice 0
            w.add_reloc(0, stub.main_call_off,
                        RelocTarget::addr(premain_sec, 0), RelocKind::REL32);
        } else {
            w.set_entry(0, 0); // stub en indice 0, offset 0
            w.add_reloc(0, stub.main_call_off,
                        RelocTarget::addr(mn.wsec, mn.off), RelocKind::REL32);
        }
        if (stub.has_import_call)
            w.add_import_call(ImportCall{stub.import_dll, stub.import_func, 0,
                                         stub.import_call_off});
    } else {
        auto it = globals.find(eff_entry);
        if (it == globals.end() || !it->second.defined) {
            err = "linker: simbolo de entrada '" + eff_entry +
                  "' no esta definido";
            return false;
        }
        w.set_entry(it->second.wsec, it->second.off);
    }

    if (!unresolved.empty()) {
        err = "linker: simbolos no resueltos:";
        for (const std::string &u : unresolved)
            err += " " + u;
        return false;
    }

    return w.write(out_path, err);
}

namespace {

// Escribe una cabecera de miembro ar (60 bytes ASCII, relleno de espacios).
void ar_put_header(std::vector<uint8_t> &out, const std::string &name16,
                   size_t data_size) {
    char hdr[60];
    std::memset(hdr, ' ', sizeof(hdr));
    // name (16), mtime (12)@16, uid (6)@28, gid (6)@34, mode (8)@40,
    // size (10)@48, fin "`\n"@58.
    std::memcpy(hdr, name16.data(), name16.size() < 16 ? name16.size() : 16);
    hdr[16] = '0';                   // mtime = 0
    hdr[28] = '0';                   // uid = 0
    hdr[34] = '0';                   // gid = 0
    std::memcpy(hdr + 40, "644", 3); // mode 0644
    char sz[16];
    int n = std::snprintf(sz, sizeof(sz), "%zu", data_size);
    if (n > 10) n = 10;
    std::memcpy(hdr + 48, sz, (size_t)n);
    hdr[58] = 0x60; // '`'
    hdr[59] = 0x0A; // '\n'
    out.insert(out.end(), hdr, hdr + 60);
}

void ar_put_u32be(std::vector<uint8_t> &out, uint32_t v) {
    out.push_back((uint8_t)(v >> 24));
    out.push_back((uint8_t)(v >> 16));
    out.push_back((uint8_t)(v >> 8));
    out.push_back((uint8_t)v);
}

inline size_t ar_even(size_t n) {
    return n + (n & 1);
}

} // namespace

bool aot_ar_create(const std::string &out_path,
                   const std::vector<std::string> &objs, std::string &err) {
    if (objs.empty()) {
        err = "ar: sin objetos de entrada";
        return false;
    }
    // 1. Parsear cada objeto: cargar bytes + extraer sus globals definidos para
    //    el indice de simbolos.
    struct Member {
        std::string name; // basename (p.ej. "gc_heap.cpp.obj")
        std::vector<uint8_t> bytes;
        std::vector<std::string> syms; // globals definidos
        std::string name_field;  // campo nombre del header ("name/" o "/N")
        uint64_t header_off = 0; // posicion de la cabecera en el .a
    };
    // Extrae los globals definidos de un objeto ya parseado.
    auto collect_globals = [](const ParsedObj &po, Member &m) {
        for (const ObjSym &sy : po.syms)
            if (sy.bind == STB_GLOBAL && sy.shndx != SHN_UNDEF &&
                sy.type != STT_SECTION && !sy.name.empty())
                m.syms.push_back(sy.name);
    };

    std::vector<Member> mem;
    // Nombres (basename) de los objetos nuevos -> reemplazan al miembro
    // homonimo si el .a ya existia (semantica de `ar r`).
    std::unordered_set<std::string> new_names;
    for (const std::string &p : objs) {
        const size_t sl = p.find_last_of("\\/");
        new_names.insert(sl == std::string::npos ? p : p.substr(sl + 1));
    }

    // 1a. UPDATE/APPEND: si el .a de salida ya existe, conservar sus miembros
    //     que NO se reemplazan por nombre.
    {
        std::vector<uint8_t> existing;
        if (read_file(out_path, existing) && ar_is_archive(existing)) {
            std::vector<ArMember> ems;
            std::vector<ArSymbol> esyms;
            std::string e2;
            if (ar_parse(existing, ems, esyms, e2)) {
                for (const ArMember &am : ems) {
                    // En un thin archive el nombre es una ruta -> el basename
                    // es el nombre de miembro.
                    std::string mname = am.name;
                    if (am.is_thin) {
                        const size_t sl = mname.find_last_of("\\/");
                        if (sl != std::string::npos)
                            mname = mname.substr(sl + 1);
                    }
                    if (new_names.count(mname)) continue; // reemplazado
                    Member m;
                    m.name = mname;
                    ParsedObj po;
                    if (!load_ar_member_bytes(out_path, existing, am, po.bytes))
                        continue; // thin: fichero externo ausente
                    std::string e3;
                    if (parse_any_obj(out_path + "(" + am.name + ")", po, e3))
                        collect_globals(po, m);
                    m.bytes = std::move(po.bytes);
                    mem.push_back(std::move(m));
                }
            }
        }
    }

    // 1b. Anadir (o reemplazar) los objetos nuevos.
    for (const std::string &p : objs) {
        Member m;
        const size_t sl = p.find_last_of("\\/");
        m.name = (sl == std::string::npos) ? p : p.substr(sl + 1);
        ParsedObj po;
        if (!parse_any_obj(p, po, err)) return false;
        collect_globals(po, m);
        m.bytes = std::move(po.bytes);
        mem.push_back(std::move(m));
    }

    // 2. Tabla de nombres largos GNU ("//"): los nombres cuya forma corta
    //    ("name/") no cabe en 16 bytes se referencian como "/<offset>".
    std::vector<uint8_t> longnames;
    for (Member &m : mem) {
        if (m.name.size() + 1 <= 16) {
            m.name_field = m.name + "/";
        } else {
            const size_t off = longnames.size();
            m.name_field = "/" + std::to_string(off);
            for (char c : m.name)
                longnames.push_back((uint8_t)c);
            longnames.push_back('/');
            longnames.push_back('\n');
        }
    }

    // 3. Indice de simbolos: contar + tamano.  offsets[i] apunta a la cabecera
    //    del miembro que define el simbolo i.
    std::vector<std::pair<std::string, size_t>>
        sym_list; // (nombre, idx miembro)
    for (size_t i = 0; i < mem.size(); ++i)
        for (const std::string &s : mem[i].syms)
            sym_list.emplace_back(s, i);
    size_t symtab_data = 4 + sym_list.size() * 4;
    for (auto &s : sym_list)
        symtab_data += s.first.size() + 1;

    // 4. Calcular las posiciones de cabecera de cada miembro.
    uint64_t pos = 8;                 // tras el magic "!<arch>\n"
    pos += 60 + ar_even(symtab_data); // miembro symtab "/"
    if (!longnames.empty()) pos += 60 + ar_even(longnames.size()); // "//"
    for (Member &m : mem) {
        m.header_off = pos;
        pos += 60 + ar_even(m.bytes.size());
    }

    // 5. Construir el buffer del .a.
    std::vector<uint8_t> out;
    const char magic[8] = {'!', '<', 'a', 'r', 'c', 'h', '>', '\n'};
    out.insert(out.end(), magic, magic + 8);

    // 5a. Miembro indice de simbolos "/".
    ar_put_header(out, "/", symtab_data);
    ar_put_u32be(out, (uint32_t)sym_list.size());
    for (auto &s : sym_list)
        ar_put_u32be(out, (uint32_t)mem[s.second].header_off);
    for (auto &s : sym_list) {
        out.insert(out.end(), s.first.begin(), s.first.end());
        out.push_back(0);
    }
    if (symtab_data & 1) out.push_back('\n'); // padding par

    // 5b. Tabla de nombres largos "//".
    if (!longnames.empty()) {
        ar_put_header(out, "//", longnames.size());
        out.insert(out.end(), longnames.begin(), longnames.end());
        if (longnames.size() & 1) out.push_back('\n');
    }

    // 5c. Cada miembro-objeto.
    for (Member &m : mem) {
        ar_put_header(out, m.name_field, m.bytes.size());
        out.insert(out.end(), m.bytes.begin(), m.bytes.end());
        if (m.bytes.size() & 1) out.push_back('\n');
    }

    // 6. Escribir a fichero.
    std::ofstream f(out_path, std::ios::binary);
    if (!f) {
        err = "ar: no se puede crear " + out_path;
        return false;
    }
    f.write(reinterpret_cast<const char *>(out.data()),
            (std::streamsize)out.size());
    if (!f) {
        err = "ar: error al escribir " + out_path;
        return false;
    }
    return true;
}

} // namespace aot
