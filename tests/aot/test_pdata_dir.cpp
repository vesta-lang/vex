/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/aot/test_pdata_dir.cpp
 * @brief El directorio de excepciones del PE apunta a `.pdata`, y solo cuando
 *        debe.
 *
 * POR QUE HACE FALTA COMPROBARLO.  Emitir la seccion `.pdata` no basta: el
 * sistema no la busca por su nombre, sino por DataDirectory[3] de la cabecera
 * opcional.  Una imagen con la tabla dentro pero sin ese directorio es, para
 * `RtlLookupFunctionEntry`, una imagen sin tabla: cada funcion pasa por hoja,
 * el desenrollado se para en el primer marco y el proceso muere sin manejador
 * y sin traza.
 *
 * Nada de eso se ve mirando el binario por encima -- la seccion esta, con sus
 * bytes correctos --, y tampoco se ve al ejecutarlo: solo aparece el dia que
 * hay una excepcion que desenrollar.  De ahi que se compruebe leyendo la
 * cabecera byte a byte y no confiando en que la seccion exista.
 *
 * El caso de que NO haya `.pdata` se comprueba igual de en serio: el directorio
 * tiene que quedarse en cero.  Un directorio apuntando a cualquier otra cosa
 * seria peor que no tenerlo, porque el sistema lo leeria.
 */

#include "aot/object_writer.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace aot;

static int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                               \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(c)) {                                                            \
            ++g_fails;                                                         \
            std::printf("  FALLO L%d: %s\n", __LINE__, #c);                    \
        }                                                                      \
    } while (0)

namespace {

std::vector<uint8_t> read_file(const std::string &path) {
    std::vector<uint8_t> out;
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) return out;
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n > 0) {
        out.resize((size_t)n);
        if (std::fread(out.data(), 1, (size_t)n, f) != (size_t)n) out.clear();
    }
    std::fclose(f);
    return out;
}

uint32_t rd_u32(const std::vector<uint8_t> &b, size_t off) {
    if (off + 4 > b.size()) return 0;
    return (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) |
           ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
}
uint16_t rd_u16(const std::vector<uint8_t> &b, size_t off) {
    if (off + 2 > b.size()) return 0;
    return (uint16_t)(b[off] | (b[off + 1] << 8));
}

/// Lo que hace falta de la cabecera para responder a la pregunta del fichero.
struct PeView {
    bool ok = false;
    uint32_t exc_rva = 0;  ///< DataDirectory[3].VirtualAddress
    uint32_t exc_size = 0; ///< DataDirectory[3].Size
    uint32_t num_dirs = 0;
    uint32_t sec_rva = 0;  ///< RVA de la seccion buscada (0 si no esta)
    uint32_t sec_vsize = 0;
    uint32_t sec_raw = 0;  ///< offset EN FICHERO, para poder leer su contenido
    bool sec_found = false;
};

/* Recorre el PE a mano en vez de usar la libreria que lo escribio: si la
 * lectura compartiera codigo con la escritura, un error de indice en la tabla
 * de directorios saldria bien en las dos y el test no lo veria. */
PeView inspect(const std::vector<uint8_t> &pe, const char *want_section) {
    PeView v;
    if (pe.size() < 0x40 || pe[0] != 'M' || pe[1] != 'Z') return v;

    const uint32_t lfanew = rd_u32(pe, 0x3C);
    if (rd_u32(pe, lfanew) != 0x00004550u) return v; // 'PE\0\0'

    const uint32_t fh = lfanew + 4;              // IMAGE_FILE_HEADER
    const uint16_t nsecs = rd_u16(pe, fh + 2);   // NumberOfSections
    const uint16_t opt_sz = rd_u16(pe, fh + 16); // SizeOfOptionalHeader
    const uint32_t opt = fh + 20;                // IMAGE_OPTIONAL_HEADER64

    if (rd_u16(pe, opt) != 0x20B) return v; // PE32+ (64 bits)

    /* NumberOfRvaAndSizes @ +108; la tabla de directorios empieza en +112 y
     * cada entrada son dos DWORD.  El de excepciones es el indice 3. */
    v.num_dirs = rd_u32(pe, opt + 108);
    if (v.num_dirs > 3) {
        v.exc_rva = rd_u32(pe, opt + 112 + 3 * 8);
        v.exc_size = rd_u32(pe, opt + 112 + 3 * 8 + 4);
    }

    // Cabeceras de seccion: 40 bytes cada una, detras de la cabecera opcional.
    const uint32_t sh0 = opt + opt_sz;
    for (uint32_t i = 0; i < nsecs; ++i) {
        const uint32_t sh = sh0 + i * 40;
        if (sh + 40 > pe.size()) break;
        char nm[9] = {0};
        std::memcpy(nm, &pe[sh], 8);
        if (std::strcmp(nm, want_section) == 0) {
            v.sec_vsize = rd_u32(pe, sh + 8);
            v.sec_rva = rd_u32(pe, sh + 12);
            v.sec_raw = rd_u32(pe, sh + 20); // PointerToRawData
            v.sec_found = true;
            break;
        }
    }
    v.ok = true;
    return v;
}

/// Un `.text` minimo y valido: el emisor exige entrada, y no se va a ejecutar.
std::vector<uint8_t> tiny_text() {
    return {0x48, 0x83, 0xEC, 0x28, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
}

/* `n` RUNTIME_FUNCTION plausibles: tres RVA de 4 bytes por entrada, ordenadas
 * por BeginAddress, que es como el sistema espera encontrarlas. */
std::vector<uint8_t> fake_pdata(uint32_t n) {
    std::vector<uint8_t> d;
    for (uint32_t i = 0; i < n; ++i) {
        const uint32_t begin = 0x1000 + i * 0x40;
        const uint32_t end = begin + 0x30;
        const uint32_t unwind = 0x4000 + i * 8;
        for (uint32_t val : {begin, end, unwind})
            for (int b = 0; b < 4; ++b)
                d.push_back((uint8_t)(val >> (b * 8)));
    }
    return d;
}

} // namespace

int main() {
    std::printf("== directorio de excepciones (.pdata) ==\n");

    // --- Con .pdata: el directorio la senala ------------------------------
    {
        ObjectWriter w(ObjFormat::PE);
        w.add_text(tiny_text());

        WriterSection s;
        s.name = ".pdata";
        s.flags = SecFlag::READ | SecFlag::DATA;
        s.data = fake_pdata(2); // 24 bytes
        w.add_section(s);

        std::string err;
        const std::string path = "pdata_dir_pe.exe";
        const bool ok = w.write(path, err);
        if (!ok) std::printf("  write error: %s\n", err.c_str());
        CHECK(ok);

        const PeView v = inspect(read_file(path), ".pdata");
        CHECK(v.ok);
        CHECK(v.sec_found);
        CHECK(v.num_dirs > 3); // si no, el directorio ni siquiera existe

        // Lo que se comprueba: el directorio apunta a ESA seccion, no a otra.
        CHECK(v.exc_rva != 0);
        CHECK(v.exc_rva == v.sec_rva);
        // Y su tamano es el de la tabla, no el de la seccion redondeada.
        CHECK(v.exc_size == 24);
        CHECK(v.exc_size % 12 == 0);
    }

    // --- Sin .pdata: el directorio se queda en cero -----------------------
    {
        ObjectWriter w(ObjFormat::PE);
        w.add_text(tiny_text());

        std::string err;
        const std::string path = "pdata_none_pe.exe";
        CHECK(w.write(path, err));

        const PeView v = inspect(read_file(path), ".pdata");
        CHECK(v.ok);
        CHECK(!v.sec_found);
        /* En cero las DOS mitades.  Un RVA a cero con tamano no nulo seria una
         * tabla que empieza en la cabecera del propio fichero. */
        CHECK(v.exc_rva == 0);
        CHECK(v.exc_size == 0);
    }

    // --- En una .dll, igual ----------------------------------------------
    {
        /* El emisor de DLL es otra funcion, con su propio montaje de la
         * cabecera, asi que se comprueba aparte: que el .exe salga bien no dice
         * nada de la .dll.  Y aqui pesa mas todavia -- el codigo de una
         * biblioteca aparece en la pila de quien la llama, asi que sin su
         * `.pdata` el desenrollado se corta al entrar en ella y se lleva por
         * delante el manejador del programa que la cargo. */
        ObjectWriter w(ObjFormat::PE);
        w.set_output_kind(OutputKind::SHARED);
        const int t = w.add_text(tiny_text());
        w.add_symbol("vx_test_export", t, 0);

        WriterSection s;
        s.name = ".pdata";
        s.flags = SecFlag::READ | SecFlag::DATA;
        s.data = fake_pdata(3); // 36 bytes
        w.add_section(s);

        std::string err;
        const std::string path = "pdata_dir_pe.dll";
        const bool ok = w.write(path, err);
        if (!ok) std::printf("  write dll error: %s\n", err.c_str());
        CHECK(ok);

        const PeView v = inspect(read_file(path), ".pdata");
        CHECK(v.ok);
        CHECK(v.sec_found);
        CHECK(v.exc_rva == v.sec_rva);
        CHECK(v.exc_size == 36);
    }

    // --- .pdata con un tamano imposible: se rechaza -----------------------
    {
        /* 10 bytes no descendingriben ninguna cantidad entera de RUNTIME_FUNCTION.
         * Publicarlo dejaria una entrada a medias al final, y el sistema la
         * leeria igual porque recorre el directorio por su tamano.  Se rechaza
         * al emitir, que es donde todavia se puede decir algo util. */
        ObjectWriter w(ObjFormat::PE);
        w.add_text(tiny_text());

        WriterSection s;
        s.name = ".pdata";
        s.flags = SecFlag::READ | SecFlag::DATA;
        s.data = std::vector<uint8_t>(10, 0);
        w.add_section(s);

        std::string err;
        const bool ok = w.write("pdata_bad_pe.exe", err);
        CHECK(!ok);
        CHECK(!err.empty()); // y dice por que, no falla en silencio
        if (ok) std::printf("  se emitio una .pdata de 10 bytes\n");
        else std::printf("  rechazada: %s\n", err.c_str());
    }

    // --- Una tabla desordenada se ORDENA al emitir ------------------------
    {
        /* El emisor es el unico punto con las direcciones definitivas, y al
         * enlazar esta seccion es la CONCATENACION de las tablas de cada
         * objeto: pegar dos tablas ordenadas da una desordenada, y el orden
         * final depende de donde caiga el codigo de cada uno, cosa que ningun
         * productor sabe por separado.  Por eso aqui se ordena en vez de
         * rechazar.
         *
         * Importa porque el sistema busca por BISECCION: una tabla desordenada
         * no da error al consultarla, devuelve la entrada equivocada -- o
         * ninguna -- para una direccion que si esta. */
        ObjectWriter w(ObjFormat::PE);
        w.add_text(tiny_text());

        std::vector<uint8_t> descending;
        for (uint32_t i = 0; i < 3; ++i) {
            const uint32_t begin = 0x3000 - i * 0x100; // a la baja: al reves
            for (uint32_t val : {begin, begin + 0x40, 0x8000u})
                for (int b = 0; b < 4; ++b)
                    descending.push_back((uint8_t)(val >> (b * 8)));
        }
        WriterSection s;
        s.name = ".pdata";
        s.flags = SecFlag::READ | SecFlag::DATA;
        s.data = descending;
        w.add_section(s);

        std::string err;
        const std::string path = "pdata_desorden_pe.exe";
        const bool ok = w.write(path, err);
        if (!ok) std::printf("  write error: %s\n", err.c_str());
        CHECK(ok);

        const std::vector<uint8_t> pe = read_file(path);
        const PeView v = inspect(pe, ".pdata");
        CHECK(v.ok && v.sec_found);
        CHECK(v.exc_size == 36); // las tres entradas siguen estando

        // Y ahora salen de menor a mayor, que es lo unico que se pedia.
        uint32_t prev = 0;
        bool ascendente = true;
        for (uint32_t k = 0; k < v.exc_size / 12; ++k) {
            const uint32_t begin = rd_u32(pe, v.sec_raw + k * 12);
            if (k && begin <= prev) ascendente = false;
            prev = begin;
        }
        CHECK(ascendente);
        std::printf("  la tabla desordenada salio %s\n",
                    ascendente ? "ordenada" : "MAL");
    }

    // --- Una entrada que acaba antes de empezar, tampoco -------------------
    {
        ObjectWriter w(ObjFormat::PE);
        w.add_text(tiny_text());

        std::vector<uint8_t> reversed;
        for (uint32_t val : {0x2000u, 0x1000u, 0x8000u}) // end < begin
            for (int b = 0; b < 4; ++b)
                reversed.push_back((uint8_t)(val >> (b * 8)));
        WriterSection s;
        s.name = ".pdata";
        s.flags = SecFlag::READ | SecFlag::DATA;
        s.data = reversed;
        w.add_section(s);

        std::string err;
        const bool ok = w.write("pdata_invertida_pe.exe", err);
        CHECK(!ok);
        if (!ok) std::printf("  entrada invertida rechazada: %s\n", err.c_str());
    }

    std::printf("--- %d checks, %d fallos ---\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
