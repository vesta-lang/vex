/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/file_read.cpp
 * @brief Lectura de ficheros por el camino corto del sistema.
 *
 * El porque de cada decision, y los numeros que la sostienen, estan en
 * `include/util/file_read.h`.  Aqui solo esta el como.
 */

#include "util/file_read.h"

#if defined(_WIN32)
#include <windows.h>
#include <winternl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <cerrno>

namespace util {

#if defined(_WIN32)

/* Se enlazan (libntdll) en vez de resolverse con GetProcAddress.  Medido, da
 * igual en tiempo -- la llamada se pierde dentro de la transicion al nucleo --
 * pero enlazar es mejor por lo demas: nada que resolver al arrancar, ningun
 * puntero que comprobar, y si un simbolo faltase el fallo saldria al cargar el
 * proceso y no a mitad de una compilacion. */
extern "C" {
NTSTATUS NTAPI NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                          POBJECT_ATTRIBUTES ObjectAttributes,
                          PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess,
                          ULONG OpenOptions);
NTSTATUS NTAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
                          PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
                          PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                          PULONG Key);
/* Para escribir hace falta `NtCreateFile` y no `NtOpenFile`: el segundo abre lo
 * que ya existe y no crea nada. */
NTSTATUS NTAPI NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                            POBJECT_ATTRIBUTES ObjectAttributes,
                            PIO_STATUS_BLOCK IoStatusBlock,
                            PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                            ULONG ShareAccess, ULONG CreateDisposition,
                            ULONG CreateOptions, PVOID EaBuffer,
                            ULONG EaLength);
NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
                           PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
                           PVOID Buffer, ULONG Length,
                           PLARGE_INTEGER ByteOffset, PULONG Key);
}

namespace {

constexpr ULONG kFileReadData = 0x0001;
constexpr ULONG kSynchronousIoNonAlert = 0x0020;
constexpr ULONG kNonDirectoryFile = 0x0040;
constexpr ULONG kDirectoryFile = 0x0001;
constexpr int kFileStandardInformation = 5;
constexpr ULONG kFileWriteData = 0x0002;
/// Crea el fichero, o lo trunca si ya estaba.
constexpr ULONG kFileOverwriteIf = 0x00000005;

/// Lo que devuelve NtQueryInformationFile para FileStandardInformation.
struct StandardInformation {
    LARGE_INTEGER allocation_size;
    LARGE_INTEGER end_of_file;
    ULONG number_of_links;
    BOOLEAN delete_pending;
    BOOLEAN directory;
};

/**
 * @brief Traduce una ruta DOS al espacio de nombres del nucleo.
 *
 * Es la misma traduccion que hace `CreateFileA` en cada apertura; hacerla aqui
 * la quita de alli.  Solo se acepta la forma simple `X:\...`: las rutas
 * relativas dependen del directorio actual del proceso y las UNC tienen su
 * propio prefijo, y ninguna de las dos merece codigo propio cuando el camino de
 * respaldo ya las resuelve bien.
 *
 * @return false si la ruta no es un camino absoluto con unidad.
 */
bool to_nt_path(const std::string &path, std::wstring &out) {
    if (path.size() < 3) return false;
    const char drive = path[0];
    const bool is_letter =
        (drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z');
    if (!is_letter || path[1] != ':') return false;
    if (path[2] != '\\' && path[2] != '/') return false;

    out.assign(L"\\??\\");
    out.reserve(4 + path.size());
    for (const char c : path) {
        // Las barras normales valen en la API de Win32 pero NO en la del
        // nucleo, que las trata como parte del nombre.
        out.push_back(
            c == '/' ? L'\\'
                     : static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    return true;
}

/// Vuelca @p handle entero en @p out.  Comun a los dos caminos de Windows.
bool read_all_from(HANDLE handle, uint64_t size, std::vector<uint8_t> &out) {
    out.resize(static_cast<size_t>(size));
    if (size == 0) return true;

    uint64_t done = 0;
    while (done < size) {
        // ReadFile no admite mas de 4 GiB de una vez; el bucle ademas cubre las
        // lecturas parciales, que en un fichero normal no pasan pero en un
        // fichero de red si.
        const uint64_t left = size - done;
        const DWORD chunk =
            left > 0x40000000ull ? 0x40000000u : static_cast<DWORD>(left);
        DWORD got = 0;
        if (!ReadFile(handle, out.data() + done, chunk, &got, nullptr) ||
            got == 0) {
            out.clear();
            return false;
        }
        done += got;
    }
    return true;
}

/// Abre un fichero ya descrito y lo vuelca entero.  Comun a la apertura por
/// ruta absoluta y a la relativa: solo cambia como se rellena @p attrs.
bool open_and_read(POBJECT_ATTRIBUTES attrs, std::vector<uint8_t> &out) {
    IO_STATUS_BLOCK io;
    HANDLE handle = nullptr;
    const NTSTATUS st = NtOpenFile(&handle, kFileReadData | SYNCHRONIZE, attrs,
                                   &io, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   kSynchronousIoNonAlert | kNonDirectoryFile);
    if (st < 0 || handle == nullptr) return false;

    StandardInformation info = {};
    bool ok = false;
    if (NtQueryInformationFile(handle, &io, &info, sizeof(info),
                               static_cast<FILE_INFORMATION_CLASS>(
                                   kFileStandardInformation)) >= 0) {
        ok = read_all_from(
            handle, static_cast<uint64_t>(info.end_of_file.QuadPart), out);
    }
    NtClose(handle);
    return ok;
}

/// Lee @p count bytes desde @p offset de un fichero ya descrito.
bool open_and_read_range(POBJECT_ATTRIBUTES attrs, uint64_t offset,
                         size_t count, std::vector<uint8_t> &out) {
    IO_STATUS_BLOCK io;
    HANDLE handle = nullptr;
    if (NtOpenFile(&handle, kFileReadData | SYNCHRONIZE, attrs, &io,
                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                   kSynchronousIoNonAlert | kNonDirectoryFile) < 0 ||
        handle == nullptr)
        return false;

    out.resize(count);
    size_t done = 0;
    bool ok = true;
    while (done < count) {
        const size_t left = count - done;
        const ULONG chunk =
            left > 0x40000000u ? 0x40000000u : static_cast<ULONG>(left);
        LARGE_INTEGER pos;
        pos.QuadPart = static_cast<LONGLONG>(offset + done);
        if (NtReadFile(handle, nullptr, nullptr, nullptr, &io,
                       out.data() + done, chunk, &pos, nullptr) < 0 ||
            io.Information == 0) {
            ok = false;
            break;
        }
        done += io.Information;
    }
    NtClose(handle);
    if (!ok || done != count) {
        out.clear();
        return false;
    }
    return true;
}

/// Rellena un UNICODE_STRING que apunta a @p s.  No copia: @p s tiene que
/// seguir viva mientras se use.
void fill_name(UNICODE_STRING &name, const std::wstring &s) {
    name.Buffer = const_cast<PWSTR>(s.c_str());
    name.Length = static_cast<USHORT>(s.size() * sizeof(wchar_t));
    name.MaximumLength = static_cast<USHORT>(name.Length + sizeof(wchar_t));
}

/// Camino corto: NtOpenFile sobre la ruta ya traducida.
bool read_via_nt(const std::wstring &nt_path, std::vector<uint8_t> &out) {
    UNICODE_STRING name;
    fill_name(name, nt_path);
    OBJECT_ATTRIBUTES attrs;
    InitializeObjectAttributes(&attrs, &name, OBJ_CASE_INSENSITIVE, nullptr,
                               nullptr);
    return open_and_read(&attrs, out);
}

/// Respaldo para lo que la traduccion no cubre: relativas, UNC, rutas raras.
bool read_via_win32(const std::string &path, std::vector<uint8_t> &out) {
    HANDLE handle = CreateFileA(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size;
    bool ok = false;
    if (GetFileSizeEx(handle, &size))
        ok = read_all_from(handle, static_cast<uint64_t>(size.QuadPart), out);
    CloseHandle(handle);
    return ok;
}

} // namespace

bool read_whole_file(const std::string &path, std::vector<uint8_t> &out) {
    out.clear();
    std::wstring nt_path;
    if (to_nt_path(path, nt_path) && read_via_nt(nt_path, out)) return true;
    // Que el camino corto falle no significa que el fichero no este: puede ser
    // una ruta que la traduccion no cubre.  Se reintenta por el largo.
    return read_via_win32(path, out);
}

bool read_file_range(const std::string &path, uint64_t offset, size_t count,
                     std::vector<uint8_t> &out) {
    out.clear();
    if (count == 0) return true;
    std::wstring nt_path;
    if (to_nt_path(path, nt_path)) {
        UNICODE_STRING name;
        fill_name(name, nt_path);
        OBJECT_ATTRIBUTES attrs;
        InitializeObjectAttributes(&attrs, &name, OBJ_CASE_INSENSITIVE, nullptr,
                                   nullptr);
        if (open_and_read_range(&attrs, offset, count, out)) return true;
    }

    // Respaldo por el camino largo, igual que en read_whole_file.
    HANDLE handle = CreateFileA(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    out.resize(count);
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.Offset = static_cast<DWORD>(offset & 0xFFFFFFFFull);
    ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
    DWORD got = 0;
    const bool ok = ReadFile(handle, out.data(), static_cast<DWORD>(count),
                             &got, &ov) != 0 &&
                    got == count;
    CloseHandle(handle);
    if (!ok) out.clear();
    return ok;
}

namespace {

/// Vuelca @p bytes por un descriptor ya abierto, en tandas.
bool write_all_to(HANDLE handle, const std::vector<uint8_t> &bytes) {
    size_t done = 0;
    while (done < bytes.size()) {
        // El contador es de 32 bits: lo grande va en varias tandas en vez de
        // truncarse en silencio.
        const size_t left = bytes.size() - done;
        const ULONG chunk =
            left > 0x20000000ull ? 0x20000000u : static_cast<ULONG>(left);
        IO_STATUS_BLOCK io;
        LARGE_INTEGER pos;
        pos.QuadPart = static_cast<LONGLONG>(done);
        if (NtWriteFile(handle, nullptr, nullptr, nullptr, &io,
                        const_cast<uint8_t *>(bytes.data()) + done, chunk, &pos,
                        nullptr) < 0 ||
            io.Information == 0)
            return false;
        done += io.Information;
    }
    return true;
}

} // namespace

bool write_whole_file(const std::string &path,
                      const std::vector<uint8_t> &bytes) {
    std::wstring nt_path;
    if (to_nt_path(path, nt_path)) {
        UNICODE_STRING name;
        fill_name(name, nt_path);
        OBJECT_ATTRIBUTES attrs;
        InitializeObjectAttributes(&attrs, &name, OBJ_CASE_INSENSITIVE, nullptr,
                                   nullptr);
        IO_STATUS_BLOCK io;
        HANDLE handle = nullptr;
        /* El tamano final se dice de ANTEMANO.  Sin eso el sistema va
         * extendiendo el fichero segun llegan los bytes, y para los 7,9 MiB de
         * un artefacto eso es trabajo repetido que se puede evitar diciendo
         * desde el principio cuanto va a ocupar. */
        LARGE_INTEGER tam;
        tam.QuadPart = static_cast<LONGLONG>(bytes.size());
        if (NtCreateFile(&handle, kFileWriteData | SYNCHRONIZE, &attrs, &io,
                         &tam, FILE_ATTRIBUTE_NORMAL,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, kFileOverwriteIf,
                         kSynchronousIoNonAlert | kNonDirectoryFile, nullptr,
                         0) >= 0 &&
            handle != nullptr) {
            const bool ok = bytes.empty() || write_all_to(handle, bytes);
            NtClose(handle);
            if (ok) return true;
        }
    }

    // Respaldo por el camino largo, igual que al leer: rutas que la traduccion
    // no cubre.
    HANDLE handle = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    size_t done = 0;
    bool ok = true;
    while (ok && done < bytes.size()) {
        const size_t left = bytes.size() - done;
        const DWORD chunk =
            left > 0x20000000ull ? 0x20000000u : static_cast<DWORD>(left);
        DWORD written = 0;
        ok = WriteFile(handle, bytes.data() + done, chunk, &written, nullptr) !=
                 0 &&
             written == chunk;
        done += written;
    }
    CloseHandle(handle);
    return ok && done == bytes.size();
}

DirectoryReader::DirectoryReader(const std::string &dir_path)
    : handle_(nullptr) {
    std::wstring nt_path;
    if (!to_nt_path(dir_path, nt_path)) return;

    UNICODE_STRING name;
    fill_name(name, nt_path);
    OBJECT_ATTRIBUTES attrs;
    InitializeObjectAttributes(&attrs, &name, OBJ_CASE_INSENSITIVE, nullptr,
                               nullptr);

    IO_STATUS_BLOCK io;
    HANDLE handle = nullptr;
    // kFileReadData sobre un directorio es FILE_LIST_DIRECTORY; y aqui se pide
    // que el objeto SI sea un directorio, al reves que al abrir un fichero.
    if (NtOpenFile(&handle, kFileReadData | SYNCHRONIZE, &attrs, &io,
                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                   kSynchronousIoNonAlert | kDirectoryFile) >= 0)
        handle_ = handle;
}

DirectoryReader::~DirectoryReader() {
    if (handle_ != nullptr) NtClose(static_cast<HANDLE>(handle_));
}

bool DirectoryReader::ok() const {
    return handle_ != nullptr;
}

bool DirectoryReader::read_file(const std::string &leaf_name,
                                std::vector<uint8_t> &out) const {
    out.clear();
    if (handle_ == nullptr) return false;
    // Un nombre de hoja no lleva separadores: si los lleva, quien llama se ha
    // equivocado de funcion y el nucleo lo interpretaria como parte del nombre.
    if (leaf_name.find('\\') != std::string::npos ||
        leaf_name.find('/') != std::string::npos)
        return false;

    std::wstring leaf;
    leaf.reserve(leaf_name.size());
    for (const char c : leaf_name)
        leaf.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));

    UNICODE_STRING name;
    fill_name(name, leaf);
    OBJECT_ATTRIBUTES attrs;
    // La diferencia esta en la raiz: el descriptor del directorio, en vez de
    // nullptr.  Con eso el nombre se resuelve DENTRO de el.
    InitializeObjectAttributes(&attrs, &name, OBJ_CASE_INSENSITIVE,
                               static_cast<HANDLE>(handle_), nullptr);
    return open_and_read(&attrs, out);
}

#else // POSIX

namespace {

/// Vuelca un descriptor ya abierto y lo cierra.  Comun a `open` y a `openat`.
bool read_all_and_close(int fd, std::vector<uint8_t> &out) {
    struct stat info;
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        ::close(fd);
        return false;
    }

    const size_t size = static_cast<size_t>(info.st_size);
    out.resize(size);
    size_t done = 0;
    while (done < size) {
        const ssize_t got = ::read(fd, out.data() + done, size - done);
        if (got < 0) {
            // Una senal a mitad de lectura no es un fallo: se reintenta.
            if (errno == EINTR) continue;
            out.clear();
            ::close(fd);
            return false;
        }
        if (got == 0) break; // El fichero encogio entre el fstat y el read.
        done += static_cast<size_t>(got);
    }
    ::close(fd);
    if (done != size) {
        out.clear();
        return false;
    }
    return true;
}

} // namespace

bool read_whole_file(const std::string &path, std::vector<uint8_t> &out) {
    out.clear();
    /* `open` + `read` ya es la llamada del sistema sin capas encima, que es
     * justo lo que se le reprocha a `ifstream`.  `mmap` seria mas barato SI el
     * que llama pudiera mirar el contenido en el sitio; como aqui se copia al
     * vector, mapear solo anadiria dos llamadas mas.  Cuando alguien necesite
     * mirar sin copiar, ese sera el momento de ofrecer una vista mapeada. */
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    return read_all_and_close(fd, out);
}

bool read_file_range(const std::string &path, uint64_t offset, size_t count,
                     std::vector<uint8_t> &out) {
    out.clear();
    if (count == 0) return true;
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;

    out.resize(count);
    size_t done = 0;
    while (done < count) {
        // `pread` lee en una posicion sin mover el cursor ni pedir un `lseek`
        // aparte, que es justo lo que hace falta aqui.
        const ssize_t got = ::pread(fd, out.data() + done, count - done,
                                    static_cast<off_t>(offset + done));
        if (got < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (got == 0) break; // se acabo el fichero antes de lo pedido
        done += static_cast<size_t>(got);
    }
    ::close(fd);
    if (done != count) {
        out.clear();
        return false;
    }
    return true;
}

bool write_whole_file(const std::string &path,
                      const std::vector<uint8_t> &bytes) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t done = 0;
    while (done < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + done, bytes.size() - done);
        if (n < 0) {
            if (errno == EINTR) continue; // una senal no es un fallo
            break;
        }
        if (n == 0) break;
        done += static_cast<size_t>(n);
    }
    ::close(fd);
    return done == bytes.size();
}

DirectoryReader::DirectoryReader(const std::string &dir_path) : fd_(-1) {
    fd_ = ::open(dir_path.c_str(), O_RDONLY | O_DIRECTORY);
}

DirectoryReader::~DirectoryReader() {
    if (fd_ >= 0) ::close(fd_);
}

bool DirectoryReader::ok() const {
    return fd_ >= 0;
}

bool DirectoryReader::read_file(const std::string &leaf_name,
                                std::vector<uint8_t> &out) const {
    out.clear();
    if (fd_ < 0) return false;
    // Un nombre de hoja no lleva separadores; con ellos esto abriria otra cosa.
    if (leaf_name.find('/') != std::string::npos) return false;
    const int fd = ::openat(fd_, leaf_name.c_str(), O_RDONLY);
    if (fd < 0) return false;
    return read_all_and_close(fd, out);
}

#endif

} // namespace util
