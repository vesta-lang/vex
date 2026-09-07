/**
 * @file vesta_gc/freestanding_shim.cpp
 * @brief Shim de runtime C++ para libvesta_gc FREESTANDING.
 *
 * Provee, en terminos de libc (malloc/free/abort), los pocos simbolos de la ABI
 * de libstdc++ que las plantillas usadas por el GC (@c std::vector, etc.)
 * referencian: @c operator @c new/delete y los helpers @c std::__throw_* /
 * @c __glibcxx_assert_fail.  Asi el archivo @c libvesta_gc.a queda con
 * dependencias SOLO de libc -- que el AOT ya resuelve via IAT/PLT -- y se
 * enlaza con NUESTRO linker (AOT.5) sin g++ ni libstdc++.
 *
 * Solo se compila en el target @c vesta_gc (con @c VESTA_GC_FREESTANDING); el
 * resto del proyecto (vmcore, vm, interp/JIT) usa el libstdc++ real, asi que
 * este shim NO afecta su comportamiento.
 */
#if defined(VESTA_GC_FREESTANDING)

#include <cstddef>
#include <cstdlib>

// --- operator new / delete -> malloc / free -------------------------------
void *operator new(std::size_t n) {
    void *p = std::malloc(n ? n : 1);
    if (!p) std::abort();
    return p;
}
void *operator new[](std::size_t n) {
    return operator new(n);
}
void operator delete(void *p) noexcept {
    std::free(p);
}
void operator delete[](void *p) noexcept {
    std::free(p);
}
void operator delete(void *p, std::size_t) noexcept {
    std::free(p);
}
void operator delete[](void *p, std::size_t) noexcept {
    std::free(p);
}

/* --- Las variantes `nothrow`, y el objeto `std::nothrow` ------------------
 *
 * Las referencia el asignador desde que las primitivas del sistema salieron a
 * `vesta_alloc`: ahi una reserva que falla DEVUELVE nulo en vez de lanzar, que
 * es lo que un asignador tiene que hacer.  Sin ellas el enlazado de un binario
 * AOT que use `gc<T>` muere con `_ZnwyRKSt9nothrow_t` sin resolver -- y no lo
 * decia el GC, lo decia el enlazador, que es donde cuesta mas verlo.
 *
 * `std::nothrow` es un OBJETO, no una funcion, asi que no basta con declararlo:
 * hay que DEFINIRLO o `_ZSt7nothrow` se queda igual de suelto.  Por eso se
 * incluye `<new>` -- cabecera freestanding, disponible sin biblioteca estandar
 * completa -- en vez de declarar el tipo a mano: con un tipo incompleto las
 * sobrecargas manglan igual, pero el objeto no se puede definir.
 *
 * Va aqui y no en el asignador porque este fichero es justo el sitio donde se
 * paga lo que libstdc++ daria y aqui no hay. */
#include <new>

namespace std {
const nothrow_t nothrow{}; // `<new>` solo lo declara `extern`
} // namespace std

void *operator new(std::size_t n, const std::nothrow_t &) noexcept {
    return std::malloc(n ? n : 1); // nulo si no hay; NO se aborta
}
void *operator new[](std::size_t n, const std::nothrow_t &tag) noexcept {
    return operator new(n, tag);
}
void operator delete(void *p, const std::nothrow_t &) noexcept {
    std::free(p);
}
void operator delete[](void *p, const std::nothrow_t &) noexcept {
    std::free(p);
}

// --- helpers de excepcion de libstdc++ -> abort ---------------------------
// Sin excepciones (-fno-exceptions) estos no se invocan en flujo normal, pero
// las plantillas STL los referencian.  Definidos en @c namespace std para que
// generen los simbolos mangled exactos (_ZSt17__throw_bad_allocv, etc.).
namespace std {
[[noreturn]] void __throw_bad_alloc() {
    std::abort();
}
[[noreturn]] void __throw_length_error(const char *) {
    std::abort();
}
[[noreturn]] void __throw_bad_array_new_length() {
    std::abort();
}
[[noreturn]] void __throw_out_of_range_fmt(const char *, ...) {
    std::abort();
}
[[noreturn]] void __throw_system_error(int) {
    std::abort();
}
// _ZSt21__glibcxx_assert_failPKciS0_S0_
[[noreturn]] void __glibcxx_assert_fail(const char *, int, const char *,
                                        const char *) noexcept {
    std::abort();
}
} // namespace std

// --- __cxa_thread_atexit (thread_local dtors) -> no-op --------------------
// El GC freestanding no tiene destructores thread_local que importen al exit.
extern "C" int __cxa_thread_atexit(void (*)(void *), void *, void *) {
    return 0;
}

// --- __dso_handle ---------------------------------------------------------
// Identificador del objeto dinamico que el codigo C++ pasa a __cxa_atexit al
// registrar destructores de estaticos.  Normalmente lo provee el arranque del
// CRT (crtbegin); en el freestanding lo definimos como un simbolo propio (su
// direccion es lo unico que importa).
extern "C" {
void *__dso_handle = nullptr;
}

// --- atexit -> no-op ------------------------------------------------------
// UCRT NO exporta atexit en ucrtbase.dll (lo provee el arranque estatico
// libucrt como envoltura de _crt_atexit).  Como el GC freestanding no hace
// teardown al exit, lo definimos como no-op para que la .a quede autocontenida
// (sin un import que el loader no podria resolver -> evita exit 127).
extern "C" int atexit(void (*)(void)) {
    return 0;
}


#endif // VESTA_GC_FREESTANDING
