cmake_minimum_required(VERSION 3.20)

# Evitar warning CMP0063 de librerias externas
if (POLICY CMP0063)
    cmake_policy(SET CMP0063 NEW)
endif ()

# Las rutas de `install()` se NORMALIZAN (`CMP0177`).
#
# La raiz del arbol privado es `.` en Windows, asi que al componer los destinos
# salen `./stdlib`, `./examples/vx` y compania.  Es la misma ruta que `stdlib`,
# pero mientras no se decide explicitamente CMake suelta un aviso por cada
# `install()` -- veinticuatro en una configuracion limpia --, y ese ruido tapa
# los avisos que si importan.
#
# NEW porque normalizar es lo que se quiere: `./stdlib` y `stdlib` tienen que
# producir la MISMA instalacion, y sin normalizar el `./` viaja dentro de la
# ruta hasta el paquete.
#
# Va AQUI y no en `VestaInstallDirs.cmake`, que seria su sitio natural: los
# ficheros que se traen con `include()` abren su propio ambito de politicas y lo
# cierran al volver, asi que fijarla alli no llegaba a las reglas `install()`.
if (POLICY CMP0177)
    cmake_policy(SET CMP0177 NEW)
endif ()

#if (WIN32)
#    message(STATUS "Compilando en Windows: activando linkado estático")
#
#    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
#else ()
#    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
#endif ()

set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "Enable verbose build output" FORCE)


# helper para imprimir propiedades relevantes de un target
function(print_target_flags tgt)
    get_target_property(_inc_dirs ${tgt} INCLUDE_DIRECTORIES)
    get_target_property(_compile_opts ${tgt} COMPILE_OPTIONS)
    get_target_property(_compile_defs ${tgt} COMPILE_DEFINITIONS)
    get_target_property(_link_opts ${tgt} LINK_OPTIONS)
    get_target_property(_link_libs ${tgt} LINK_LIBRARIES)

    message(STATUS "---- Target: ${tgt} ----")
    message(STATUS "INCLUDE_DIRECTORIES: ${_inc_dirs}")
    message(STATUS "COMPILE_OPTIONS: ${_compile_opts}")
    message(STATUS "COMPILE_DEFINITIONS: ${_compile_defs}")
    message(STATUS "LINK_OPTIONS: ${_link_opts}")
    message(STATUS "LINK_LIBRARIES: ${_link_libs}")
endfunction()

# si no necesitamos los ejecutables de fuzzing,
# deshabilitarlos usando opciones de Keystone/LLVM
set(ENABLE_FUZZING OFF CACHE BOOL "" FORCE)


# Configuracion Capstone
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "Enable ARM")
set(CAPSTONE_AARCH64_SUPPORT ON CACHE BOOL "Enable ARM64")
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "Enable X86/x64")

# Desactivar todos los demas backends
set(CAPSTONE_MIPS_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_PPC_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_SYSTEMZ_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_M680X_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_EVM_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_MOS65XX_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_WASM_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_BPF_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_RISCV_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_SH_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_TRICORE_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_ALPHA_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_HPPA_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_LOONGARCH_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_XTENSA_SUPPORT OFF CACHE BOOL "")
set(CAPSTONE_ARC_SUPPORT OFF CACHE BOOL "")


# Configuracion Keystone
set(ENABLE_ARM_TARGET ON CACHE BOOL "")
set(ENABLE_AARCH64_TARGET ON CACHE BOOL "")
set(ENABLE_X86_TARGET ON CACHE BOOL "")

# Desactivar los demas backends
set(ENABLE_MIPS_TARGET OFF CACHE BOOL "")
set(ENABLE_PPC_TARGET OFF CACHE BOOL "")
set(ENABLE_SPARC_TARGET OFF CACHE BOOL "")
set(ENABLE_SYSTEMZ_TARGET OFF CACHE BOOL "")
set(ENABLE_HEXAGON_TARGET OFF CACHE BOOL "")
set(ENABLE_M68K_TARGET OFF CACHE BOOL "")
set(ENABLE_TMS320C64X_TARGET OFF CACHE BOOL "")
set(ENABLE_M680X_TARGET OFF CACHE BOOL "")
set(ENABLE_EVM_TARGET OFF CACHE BOOL "")
set(ENABLE_MOS65XX_TARGET OFF CACHE BOOL "")
set(ENABLE_WASM_TARGET OFF CACHE BOOL "")
set(ENABLE_BPF_TARGET OFF CACHE BOOL "")
set(ENABLE_RISCV_TARGET OFF CACHE BOOL "")
set(ENABLE_SH_TARGET OFF CACHE BOOL "")
set(ENABLE_TRICORE_TARGET OFF CACHE BOOL "")
set(ENABLE_ALPHA_TARGET OFF CACHE BOOL "")
set(ENABLE_HPPA_TARGET OFF CACHE BOOL "")
set(ENABLE_LOONGARCH_TARGET OFF CACHE BOOL "")
set(ENABLE_XTENSA_TARGET OFF CACHE BOOL "")
set(ENABLE_ARC_TARGET OFF CACHE BOOL "")

project(VMProject
        VERSION 1.0.0
        DESCRIPTION "VestaVM: register-based VM + Vex frontend"
        LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Cache de compilador (ver cmake/EnsureCcache.cmake).
#
# Va aqui, justo despues de `project()`: los lanzadores del compilador hay que
# fijarlos antes de que se cree ningun target, porque cada uno se queda con el
# valor que hubiera en ese momento.
# ---------------------------------------------------------------------------
option(VESTA_USE_CCACHE "Usar cache de compilador (se descarga si no hay)" ON)
include("${CMAKE_SOURCE_DIR}/cmake/EnsureCcache.cmake")
vesta_setup_ccache()

# Nivel minimo de API de Windows.  Algunas funciones que usa el runtime
# (p.ej. GetCurrentThreadStackLimits, Win8+) exigen _WIN32_WINNT>=0x0602.
# msys/ucrt64 lo trae alto por defecto; TDM-GCC (mingw-w64 mas antiguo) lo
# deja bajo y oculta el simbolo -> se define aqui a Win10 (0x0A00) para que
# el proyecto compile con AMBOS toolchains. 
if (WIN32 AND NOT DEFINED VESTA_WIN32_WINNT)
    add_compile_definitions(_WIN32_WINNT=0x0A00 WINVER=0x0A00)
endif ()

# versiones del compilador y la VM expuestas al @Target.
# Permite que usuarios escriban @Target("compiler>=1.0") y obtengan
# resolucion en compile-time sin hardcodear los numeros en C++.  Se
# bumpean al subir mayor/minor; un sprint futuro puede separar
# vx-compiler vs runtime-VM si divergen.
set(VX_COMPILER_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(VX_COMPILER_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(VX_COMPILER_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(VX_VM_VERSION_MAJOR       ${PROJECT_VERSION_MAJOR})
set(VX_VM_VERSION_MINOR       ${PROJECT_VERSION_MINOR})
set(VX_VM_VERSION_PATCH       ${PROJECT_VERSION_PATCH})

# Generar include/vx/version_generated.h con las constantes para que
# el frontend lea las versiones desde un solo punto.  Build incremental
# regenera automaticamente cuando cambia el numero en este CMakeLists.
configure_file(
    "${CMAKE_SOURCE_DIR}/cmake/version_generated.h.in"
    "${CMAKE_BINARY_DIR}/generated/include/vx/version_generated.h"
    @ONLY
)
include_directories(BEFORE "${CMAKE_BINARY_DIR}/generated/include")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Codigo posicion-independiente (PIC) en TODOS los objetos.  El proyecto
# produce ademas de los ejecutables una libreria COMPARTIDA embebible
# (vesta_ffi -> libvesta.so/.dll) que enlaza las libs estaticas del proyecto y
# las vendored (vx_lib, capstone, keystone, sqlite3, ...).  En ELF, enlazar un
# objeto NO-PIC dentro de un .so falla (relocaciones R_X86_64_PC32 /
# R_X86_64_TPOFF32 "recompile with -fPIC"), p.ej. el TLS `thread_local` de
# vx_lib o simbolos de capstone.  Con PIC global el shared object enlaza en
# Linux; en x86-64 el coste de PIC es despreciable y en Windows/MinGW el flag
# es inocuo para los .a.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()


# GCC 16 (UCRT64) tiene un ICE en el pase de var-tracking a -O3 sobre algunas
# funciones del frontend.  var-tracking es info de DEBUG -> en Release
# (-DNDEBUG, sin -g) no aporta NADA y se puede desactivar SIN tocar el nivel
# de optimizacion: -O3 sigue intacto (calidad del codigo identica).  Solo GNU.
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    string(APPEND CMAKE_CXX_FLAGS_RELEASE " -fno-var-tracking")
    string(APPEND CMAKE_C_FLAGS_RELEASE " -fno-var-tracking")
endif ()

# ---------------------------------------------------------------------------
#  Configuracion Profile: Release CON simbolos, para perfilar de verdad
# ---------------------------------------------------------------------------
#
# Por que no vale ninguna de las que ya hay.  Un perfil sobre Debug dice QUE
# codigo existe, no CUANTO pesa: sin meter en linea, cualquier funcion pequena
# llamada a menudo copa la lista.  Eso costo cinco iteraciones tirando de un
# hilo -- el mapa del analisis de rangos -- que en Release pesa el 2 %.  Y
# RelWithDebInfo aqui es -O1: otro nivel de optimizacion es otro programa, y por
# tanto otras proporciones.
#
# Profile PARTE de los flags de Release (por eso va DESPUES del bloque de
# arriba: hereda tambien -fno-var-tracking, que con -g volveria a activarse y es
# lo que dispara el ICE de GCC 16 a -O3) y solo anade lo que el perfilador
# necesita para atribuir tiempo:
#
#   -g                       simbolos; sin ellos hay que traducir direcciones a mano
#   -fno-omit-frame-pointer  pilas de llamada fiables (Release las omite)
#
# El nivel de optimizacion NO se toca.  Si cambiara, volveriamos a medir un
# programa distinto del que se ejecuta, que es justo el error que esto evita.
#
#   cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Profile -B cmake-build-profile
set(CMAKE_CXX_FLAGS_PROFILE "${CMAKE_CXX_FLAGS_RELEASE} -g -fno-omit-frame-pointer"
        CACHE STRING "Flags C++ para perfilar (Release + simbolos)" FORCE)
set(CMAKE_C_FLAGS_PROFILE "${CMAKE_C_FLAGS_RELEASE} -g -fno-omit-frame-pointer"
        CACHE STRING "Flags C para perfilar (Release + simbolos)" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_PROFILE "${CMAKE_EXE_LINKER_FLAGS_RELEASE}"
        CACHE STRING "Flags de enlazado para perfilar" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_PROFILE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE}"
        CACHE STRING "Flags de enlazado dinamico para perfilar" FORCE)
if (CMAKE_CONFIGURATION_TYPES)
    list(APPEND CMAKE_CONFIGURATION_TYPES Profile)
    list(REMOVE_DUPLICATES CMAKE_CONFIGURATION_TYPES)
endif ()


# SQLite library (statica)
add_library(sqlite3 STATIC
        libs/SourceCode/sqlite/sqlite3.c
)
target_include_directories(sqlite3 PUBLIC
        libs/SourceCode/sqlite
)

# miniz: deflate en un solo fichero, licencia MIT.
#
# POR QUE.  La seccion `@ir` del artefacto es el 76% de su tamano -- 5,75 MiB de
# 7,56 en un proyecto de 6k lineas -- y comprime muchisimo por ser una
# serializacion muy repetitiva.  Medido sobre esa seccion real: nivel 3 da 13,8x
# en 22,9 ms y nivel 6 da 15,2x en 56,8; descomprimir, ~4 ms en los dos.
#
# POR QUE MINIZ Y NO OTRO.  Se probaron los compresores que YA trae el sistema
# (`RtlCompressBuffer` de ntdll, que ya enlazamos, y la Compression API de
# cabinet).  XPRESS_HUFF es mas rapido -- 10,7x en 4,9 ms -- pero es de Windows,
# y un artefacto comprimido asi no lo abre nadie fuera.  Deflate lo entiende
# cualquier herramienta, y eso vale mas que 3 ms en algo que se escribe una vez.
#
# Y frente a zlib: mismo formato y mismos numeros, pero UN fichero en vez de
# quince.  Se compila como C: `miniz.c` declara un `const` de forma tentativa,
# que C permite y C++ rechaza.
add_library(miniz STATIC
        libs/SourceCode/miniz/miniz.c
)
target_include_directories(miniz PUBLIC
        libs/SourceCode/miniz
)
set_target_properties(miniz PROPERTIES LINKER_LANGUAGE C)

# Preprocesador vpp (opcional — activado por defecto)
option(VESTA_BUILD_PREPROCESSOR "Compilar el preprocesador vpp e integrarlo en el ensamblador" ON)
if(VESTA_BUILD_PREPROCESSOR)
    # deshabilitar el ejecutable y los tests propios del preprocesador cuando se compila
    # como submodulo del proyecto principal, para no duplicar binarios
    set(VPP_BUILD_EXE   OFF CACHE BOOL "" FORCE)
    set(VPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    add_subdirectory(preprocessor)
endif()

# Include directories globales
set(VM_INCLUDES
        ${CMAKE_SOURCE_DIR}/include
        libs/SourceCode/json
        libs/SourceCode/cxxopts
        libs/SourceCode/capstone/include
        libs/SourceCode/keystone/include
        libs/SourceCode/DistanciaLevenshtein
)
if(VESTA_BUILD_PREPROCESSOR)
    list(APPEND VM_INCLUDES ${CMAKE_SOURCE_DIR}/preprocessor/include)
endif()

# ---------------------------------------------------------------------------
# OpenSSL centralizado en el target INTERFACE `vesta_openssl`.
# ---------------------------------------------------------------------------
# UNICO punto de verdad de la linkadura de OpenSSL: cada consumidor (vm,
# vx_lib, vmcore, vesta_lsp, vesta_ffi, vesta_rt, tests) enlaza `vesta_openssl`
# y nada mas.  Se define AQUI, antes del primer add_subdirectory que lo use.
#
# OpenSSL SIEMPRE ESTATICO -- el binario final es standalone, sin depender de
# libssl-3-x64.dll / libcrypto-3-x64.dll.  Dos vias, en orden:
#   1. las .a del sysroot del compilador, si el toolchain las trae (MSYS2 si;
#      gratis e instantaneo).
#   2. si no (p.ej. TDM-GCC no las trae), COMPILAR OpenSSL desde el tarball
#      OFICIAL con el MISMO compilador (BuildOpenSSLStatic.cmake): portable,
#      multi-compilador, auto-descarga con SHA-256 fijado.  NUNCA se cae a DLLs.
add_library(vesta_openssl INTERFACE)

if (WIN32)
    get_filename_component(_cc_bin    "${CMAKE_C_COMPILER}" DIRECTORY)
    get_filename_component(_ucrt_root "${_cc_bin}"          DIRECTORY)
    set(_ossl_a_ssl    "${_ucrt_root}/lib/libssl.a")
    set(_ossl_a_crypto "${_ucrt_root}/lib/libcrypto.a")

    if (EXISTS "${_ossl_a_ssl}" AND EXISTS "${_ossl_a_crypto}")
        # Via 1: .a del sysroot (el toolchain ya las trae).
        message(STATUS "[OpenSSL] enlace ESTATICO desde el sysroot: ${_ossl_a_ssl}")
        target_include_directories(vesta_openssl INTERFACE "${_ucrt_root}/include")
        target_link_libraries(vesta_openssl INTERFACE
                "${_ossl_a_ssl}" "${_ossl_a_crypto}" crypt32 gdi32 ws2_32)
    else ()
        # Via 2: compilar desde fuente con el compilador del build.  Ruta
        # absoluta: CMAKE_MODULE_PATH todavia no incluye cmake/ en este punto.
        include("${CMAKE_SOURCE_DIR}/cmake/BuildOpenSSLStatic.cmake")
        vesta_build_openssl_static()
        if (NOT VESTA_OSSL_STATIC_OK)
            message(FATAL_ERROR "[OpenSSL] no se pudo obtener OpenSSL estatico.")
        endif()
        target_include_directories(vesta_openssl INTERFACE "${VESTA_OSSL_STATIC_INCLUDE}")
        # ssl antes que crypto; luego las deps Win32 de OpenSSL (crypt32 =
        # almacen de certificados; gdi32/ws2_32 = RNG y sockets).
        target_link_libraries(vesta_openssl INTERFACE
                "${VESTA_OSSL_STATIC_SSL}" "${VESTA_OSSL_STATIC_CRYPTO}"
                crypt32 gdi32 ws2_32)
    endif ()
    # Siempre estatico -> el empaquetado NO envia DLLs (VestaPackaging.cmake).
    set(VESTA_OPENSSL_STATIC ON CACHE INTERNAL "OpenSSL embebido en el binario")
else ()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(vesta_openssl INTERFACE OpenSSL::SSL OpenSSL::Crypto)
    set(VESTA_OPENSSL_STATIC OFF CACHE INTERNAL "OpenSSL embebido en el binario")
endif ()

# Frontend del lenguaje Vex como libreria estatica aislada (vx_lib).
# Decision arquitectonica: el frontend del HLL se compila
# fuera del GLOB principal y se enlaza al ejecutable como dependencia
# explicita, prefigurando la futura libvesta_rt.
# ---------------------------------------------------------------------------
# vxdbg: el grafo de conocimiento del programa.
#
# Libreria propia y no parte del frontend porque no es de ningun lenguaje NI de
# ninguna maquina: lo producen los compiladores y lo consume quien depura, y los
# dos tienen que poder enlazarlo sin arrastrarse el uno al otro.  Mientras vivio
# dentro del frontend, el runtime no podia usarlo -- no puede depender de el --
# y la traza de un fallo se quedaba sin poder explicar nada.
# ---------------------------------------------------------------------------
add_library(vxdbg_lib STATIC
    src/vxdbg/ids.cpp
    src/util/serialize.cpp
    src/vxdbg/store.cpp
    src/vxdbg/pack_store.cpp
    src/vxdbg/maintenance.cpp
    src/vxdbg/reachable.cpp
    src/vxdbg/lowering_map.cpp
    src/vxdbg/backend_meta.cpp
    src/vxdbg/codec_source.cpp
    src/vxdbg/codec_backend.cpp
    src/vxdbg/semantic_resolve.cpp
    src/vxdbg/roots.cpp
    src/vxdbg/store_source.cpp
    src/vxdbg/resolver.cpp
    src/vxdbg/capabilities.cpp
)
target_include_directories(vxdbg_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# Los codecs comparten un header interno que no es parte de su API publica.
target_include_directories(vxdbg_lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/vxdbg)
target_compile_features(vxdbg_lib PUBLIC cxx_std_17)

# ---------------------------------------------------------------------------
# diag_lib: el catalogo de diagnosticos, en todos los idiomas.
#
# Libreria propia por el mismo motivo que vxdbg: no es del frontend.  Los
# fallos en EJECUCION tambien son diagnosticos y tambien se cuentan en el
# idioma de quien los lee, y el runtime no puede depender del compilador.
# ---------------------------------------------------------------------------
add_library(diag_lib STATIC
    src/vx/diag/diag_catalog.cpp
    src/vx/gen/diag_catalog_gen.cpp
)
target_include_directories(diag_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(diag_lib PUBLIC cxx_std_17)

add_subdirectory(src/vx)

# Sources del ejecutable principal.  Se EXCLUYEN los .cpp de src/vx/
# porque ya se compilan dentro de vx_lib (incluirlos en ambos lados
# causaria definicion multiple de simbolos en el linker).
file(GLOB_RECURSE VM_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/SourceCode/DistanciaLevenshtein/Levenshtein_c.c
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/SourceCode/DistanciaLevenshtein/Levenshtein.cpp
)
list(FILTER VM_SOURCES EXCLUDE REGEX "/src/vx/")
# Port transpiler IR -> codigo (C, futuro Java/JS) vive en vx_lib (ver
# src/vx/CMakeLists.txt).  Excluir para evitar definicion duplicada.
list(FILTER VM_SOURCES EXCLUDE REGEX "/src/port/")
# Subsistema de coste (analyze::bigo) vive en vx_lib para que los renderers
# de diagramas (tambien en vx_lib) puedan anotar el coste por funcion.  Solo
# depende de ir::IrModule.  Excluir aqui para evitar definicion duplicada.
list(FILTER VM_SOURCES EXCLUDE REGEX "/src/analyze/")
# El subsistema de depuracion (vxdbg) se compila dentro de vx_lib, que es quien
# lo puebla desde el frontend.  Excluirlo aqui para no definirlo dos veces.
list(FILTER VM_SOURCES EXCLUDE REGEX "/src/vxdbg/")
# La API C embebible (src/capi/) solo forma parte de la libreria compartida
# vesta_ffi (con VESTA_BUILD_DLL); excluirla del ejecutable `vm` y de vmcore
# para no compilar sus definiciones dllexport/dllimport fuera de contexto.
list(FILTER VM_SOURCES EXCLUDE REGEX "/src/capi/")
# El servidor LSP (src/lsp/) es un binario aparte (vesta_lsp) con su propio
# main(); excluirlo del ejecutable `vm` y de vmcore para no duplicar main ni
# arrastrar el dispatcher LSP donde no se usa.
list(FILTER VM_SOURCES EXCLUDE REGEX "/src/lsp/")
# El driver de compilacion reutilizable (src/toolchain/) es su propia libreria
# estatica (vesta_toolchain): pega el frontend (vx_lib) con el back-end de
# ensamblado (vmcore) sin meterlo en vmcore (que no debe depender de vx_lib).
list(FILTER VM_SOURCES EXCLUDE REGEX "/src/toolchain/")
# main.cpp se agrega explicitamente (GLOB_RECURSE con "main.cpp" encontraria
# tambien preprocessor/src/main.cpp y causaria definicion multiple de main)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_closure.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_spimm.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_pattern.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_async.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_weak.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_sync.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_generic.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_distrib.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_exc.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_string.cpp)

# Modulo de programacion distribuida (VDP protocol)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/mailbox.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/dirty_tracker.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/node_registry.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/vdp_session.cpp)
list(APPEND VM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/dist_runtime.cpp)


set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_USE_LTO OFF CACHE BOOL "" FORCE)

# Nota: las reglas install() de estos submodulos de terceros (keystone.pc y
# demas) NO entran en el instalador de VestaVM porque el empaquetado
# (cmake/VestaPackaging.cmake) usa instalacion POR-COMPONENTE: CPack solo
# procesa los componentes de CPACK_COMPONENTS_ALL, nunca el "Unspecified" donde
# caen los terceros.  Dejarlos FUERA del instalador no basta, ojo: el paso
# previo de CPack construye el objetivo completo, asi que lo que no llega al
# instalador igualmente hay que poder construirlo -- o no construirlo, que es
# lo que se hace mas abajo con la herramienta de linea de comandos de keystone.

# Capstone (desensamblador)
add_subdirectory(libs/SourceCode/capstone)

# Keystone (ensamblador).  Solo la biblioteca: su herramienta de linea de
# comandos (kstool) no la usa nadie aqui y ademas no enlaza con MinGW, porque
# usa getopt y esa no viene con el.  Antes se construia igualmente y se tiraba
# -- el propio empaquetado ya deja fuera lo que instalan los submodulos de
# terceros -- pero el paso previo de CPack construye el objetivo completo, asi
# que generar el instalador fallaba por una herramienta que no llega a el.
set(BUILD_LIBS_ONLY ON CACHE BOOL "" FORCE)

# Los scripts de shell de keystone, con saltos de linea de Unix.
#
# Keystone averigua la arquitectura del anfitrion ejecutando `sh config.guess`,
# y en Linux eso moria con "Syntax error: word unexpected": el repo se trabaja
# desde Windows con `core.autocrlf=true`, que deja el fichero con CRLF, y el
# retorno de carro se cuela dentro de la ultima palabra de cada linea.  CMake
# abortaba antes de compilar nada, con un mensaje que no menciona los saltos.
#
# Se normaliza aqui y no con `.gitattributes` porque keystone es un SUBMODULO:
# los atributos de la raiz no gobiernan lo que hay dentro, asi que un clon
# limpio volveria a traerlo con CRLF.  Reescribir solo cuando hace falta deja
# el arbol del submodulo sin tocar en el caso normal.
foreach(_ks_sh "libs/SourceCode/keystone/llvm/cmake/config.guess"
               "libs/SourceCode/keystone/llvm/cmake/config.sub")
    set(_ks_path "${CMAKE_SOURCE_DIR}/${_ks_sh}")
    if (EXISTS "${_ks_path}")
        file(READ "${_ks_path}" _ks_txt)
        string(FIND "${_ks_txt}" "\r\n" _ks_crlf)
        if (NOT _ks_crlf EQUAL -1)
            string(REPLACE "\r\n" "\n" _ks_txt "${_ks_txt}")
            file(WRITE "${_ks_path}" "${_ks_txt}")
            message(STATUS "[keystone] ${_ks_sh}: saltos de linea normalizados a Unix")
        endif()
    endif()
endforeach()

add_subdirectory(libs/SourceCode/keystone)

# LibPEparse (emisor/parser de PE/COFF/ELF, C puro generico) -- usado por el
# backend AOT (Phase AOT.4) para emitir objetos/ejecutables nativos.  Los
# ejemplos de la lib quedan OFF al incluirse como subdirectorio.
add_subdirectory(libs/SourceCode/LibPEparse)

# Shim C del emisor AOT (aot_emit_shim.c): frontera entre el AOT C++ y
# LibPEparse.  Se compila como C (donde las cabeceras de LibPEparse -- con
# uniones anonimas y macros ELF -- compilan sin friccion C/C++) y expone la ABI
# plana de include/aot/aot_emit_shim.h.  Enlaza LibPEparse de forma PUBLIC, asi
# que linkar aot_emit arrastra LibPEparse transitivamente.
# Desacople multi-arch de la emision: el shim se parte en aot/common/ (arch-
# neutral) + aot/x86_64 + aot/x86_32 + aot/x86_16 + aot/arm64.  Los .c de
# emision incluyen aot/common/aot_emit_internal.h RELATIVO a su fichero (no se
# mete src/ en el include-path).
add_library(aot_emit STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/aot/common/aot_emit_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/aot/x86_64/aot_emit_x86_64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/aot/x86_32/aot_emit_x86_32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/aot/x86_16/aot_emit_x86_16.c)
target_include_directories(aot_emit PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(aot_emit PUBLIC LibPEparse)


# ---------------------------------------------------------------------------
# Opciones de codigo de Release, en UNA lista.
#
# Esta suelta a proposito: Release y Profile tienen que compilar EXACTAMENTE el
# mismo codigo, y la unica forma de garantizarlo es que compartan la lista en
# vez de tener cada uno su copia (dos copias acaban divergiendo, y entonces el
# perfil describe un programa que no es el que se ejecuta).  Lo unico que
# cambia entre ambas es el marco de pila y los simbolos.
# Para QUE procesador se afina.
#
# `-march` se queda en la linea base `x86-64`: no se emite ni una instruccion
# fuera de ella, asi que el binario arranca en cualquier x86-64.  `-mtune` NO
# cambia que instrucciones son legales, solo como se ordenan dentro de ese
# conjunto -- afinar para otra CPU nunca impide ejecutar --.
#
# Por eso el valor por defecto es `native`: en desarrollo interesa el codigo
# mejor ordenado para TU maquina.  Pero un paquete que se publica no debe salir
# afinado para quien lo construyo, ni depender de quien lo construyo para dar el
# mismo binario, asi que el empaquetado configura con `generic`.
set(VESTA_TUNE "native" CACHE STRING
    "Para que microarquitectura se afina (-mtune).  `generic` al publicar.")

# NO se usa `-ffast-math`.
#
# Vesta IMPLEMENTA IEEE 754, asi que el C++ que la implementa no puede
# compilarse suponiendo que los casos raros de IEEE no ocurren: eso es quitarle
# al codigo la premisa sobre la que esta escrito.  Lo que costaba tenerlo se
# midio: `NaN == NaN` daba `true` en un programa Vesta real, y peor aun, el
# resultado dependia de si el optimizador habia mirado esa expresion o no.
#
# Antes se ponia global y se EXIMIAN los ficheros que hiciera falta.  Eso es una
# lista de exclusiones, y su modo de fallar es el peor posible: al anadir un
# fichero que calcule un resultado del usuario -- un plegado en el JIT, otro en
# el AOT --, olvidarse no da error, da OTRO RESULTADO.  Ya paso:
# `exec_instruction_float.cpp` se eximio en junio de 2026 y `ir_optimizer.cpp`
# se quedo fuera dos meses y medio, plegando comparaciones con NaN.
#
# Sin el flag, olvidarse significa "va un poco mas lento", que es el lado
# correcto donde equivocarse.  Y aqui apenas hay nada que perder: `-ffast-math`
# solo toca aritmetica de coma flotante, y este compilador se pasa la vida
# persiguiendo punteros, mirando tablas y manejando cadenas.
set(VESTA_OPTS_CODIGO_RELEASE
        -O3
        -march=x86-64
        -mtune=${VESTA_TUNE}
        -fstrict-aliasing
        -fno-plt
        -fvisibility=hidden
        -ffunction-sections
        -fdata-sections
        -DNDEBUG
)

# ---------------------------------------------------------------------------
# Con que se compila el codigo de la maquina.  UN sitio, no uno por target.
#
# Estas opciones vivian solo en `vm`, y `vmcore` -- las MISMAS fuentes -- se
# compilaba sin ellas: sin `-pedantic-errors`, sin los flags de Release y, en
# Debug, sin `MODE_DEBUG_ENABLE`.  O sea que no eran dos copias del mismo
# trabajo, eran dos programas distintos, y el de los tests no era el que se
# entrega.  Compartir la lista es lo que permite que UNA compilacion sirva a
# los dos.
# ---------------------------------------------------------------------------
add_library(vesta_vm_flags INTERFACE)
target_include_directories(vesta_vm_flags INTERFACE ${VM_INCLUDES})
target_compile_options(vesta_vm_flags INTERFACE
        -D__STDC_LIMIT_MACROS
        -D__STDC_CONSTANT_MACROS
        -pedantic-errors
)
target_compile_options(vesta_vm_flags INTERFACE
        # En Debug entran tambien las comprobaciones internas y el volcado de la
        # emision.  Las tenian solo los tests, y eso significaba que el codigo
        # que probaban no era el mismo que se compilaba aqui: si alguna de esas
        # macros cambiara el tamano de una estructura, las dos mitades del
        # enlace no coincidirian y el fallo saldria en ejecucion.
        $<$<CONFIG:Debug>:
        -g -O0 -Wall -Wextra -fno-omit-frame-pointer -DMODE_DEBUG_ENABLE
        -DVM_DEBUG_CHECKS -DDEBUG_EMIT
        >
        $<$<CONFIG:Release>:${VESTA_OPTS_CODIGO_RELEASE};-fomit-frame-pointer>
        # Mismo codigo que Release; solo se anade con que atribuir el tiempo.
        $<$<CONFIG:Profile>:${VESTA_OPTS_CODIGO_RELEASE};-g;-fno-omit-frame-pointer>
        $<$<CONFIG:RelWithDebInfo>:-fpermissive -g -O1 -fno-omit-frame-pointer>
)

# ---------------------------------------------------------------------------
# El codigo de la maquina, compilado UNA vez.
#
# Antes `vm` se declaraba con todas las fuentes dentro y `vmcore` volvia a
# declararlas: dos compilaciones completas de lo mismo, ~185 objetos cada una.
# Ahora se compila aqui y `vm` solo aporta su `main.cpp`.
#
# `main.cpp` se queda FUERA del archivo: si estuviera dentro, su objeto
# chocaria con el del ejecutable al enlazar.
# ---------------------------------------------------------------------------
set(VM_CORE_SOURCES ${VM_SOURCES})
list(REMOVE_ITEM VM_CORE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)

# Lo que ya compila `vx_lib` no se vuelve a compilar aqui.
#
# Once ficheros de `src/analysis/` estaban en las dos listas: en la de `vx_lib`,
# escrita a mano, y en el comodin de `src/` de la maquina.  Se compilaban dos
# veces y ademas definian el mismo simbolo dos veces -- lo que no reventaba solo
# porque el enlazador se quedaba con la copia que venia suelta en la linea y no
# llegaba a abrir el archivo.
#
# Se descuenta preguntandole al propio target en vez de manteniendo una segunda
# lista: dos listas escritas a mano acaban separandose, y el sintoma seria otra
# vez un simbolo duplicado en un enlace que hoy funciona.
foreach (_lib vx_lib vxdbg_lib diag_lib)
    get_target_property(_lib_srcs ${_lib} SOURCES)
    get_target_property(_lib_dir  ${_lib} SOURCE_DIR)
    if (NOT _lib_srcs)
        continue()
    endif()
    foreach (_s IN LISTS _lib_srcs)
        # Las rutas relativas de un target son relativas a SU directorio.
        if (NOT IS_ABSOLUTE "${_s}")
            set(_s "${_lib_dir}/${_s}")
        endif()
        list(REMOVE_ITEM VM_CORE_SOURCES "${_s}")
    endforeach()
endforeach()
add_library(vmcore STATIC ${VM_CORE_SOURCES})
target_link_libraries(vmcore PUBLIC vesta_vm_flags miniz)

# NO hay cabeceras precompiladas, y es una decision MEDIDA, no un olvido.
#
# Se probaron y salieron PEOR: `vmcore` paso de 378,8 s a 408,0 s de CPU (+7,7%)
# con el precompilado puesto.  La razon la da `-ftime-report` sobre una de las
# unidades mas caras del proyecto (`lowering.cpp`, ~32 s):
#
#     parsing               1,49 s    5%
#     plantillas diferidas  0,92 s    3%
#     optimizar y generar  29,20 s   92%
#
# Un precompilado solo puede tocar ese 5-8%, y a cambio obliga a CADA unidad a
# cargar cabeceras que muchas no usaban -- lo que en las unidades pequenas, que
# son mayoria, cuesta mas de lo que ahorra.  A `-O3` el tiempo esta en el
# optimizador, no en leer cabeceras.
#
# Lo que si mueve la aguja aqui es no compilar dos veces lo mismo (ver arriba).

add_executable(vm ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
        # El subcomando `vm vxdbg` vive aqui y no en vxdbg_lib: usa
        # default_vxdbg_dir(), que es de vx_lib, y vx_lib ya depende de
        # vxdbg_lib.  Ponerlo alli invertiria las capas por una funcion.
        ${CMAKE_CURRENT_SOURCE_DIR}/src/vxdbg/store_cli.cpp)
# ARCHIVO COMPLETO, no el archivo a secas.
#
# De un archivo el enlazador solo saca los objetos cuyos simbolos alguien pidio,
# y en este codigo hay unidades que no exportan nada que se llame por su nombre:
# se registran solas al arrancar (productores del ASA, contratos de efectos,
# trampolines del runtime).  Nadie las referencia, asi que un enlace normal las
# dejaria fuera y el programa arrancaria SIN ellas -- sin un solo error.
#
# Con los objetos sueltos en la linea de enlace eso no podia pasar; al pasar a
# compilar el nucleo una vez, hay que pedirlo explicitamente.
target_link_libraries(vm PRIVATE $<LINK_LIBRARY:WHOLE_ARCHIVE,vmcore>)

# Fecha/hora del build + hash de git para `vesta --version`.  Un target ALL
# que corre SIEMPRE (out-of-date por diseno) regenera el header con el
# timestamp del momento; solo lo consume src/cli/version_info.cpp, asi que el
# rebuild constante afecta a esa unica TU pequena, no a todo main.cpp.
set(VESTA_BUILD_INFO_HEADER
    "${CMAKE_BINARY_DIR}/generated/include/version/build_info_generated.h")
add_custom_target(vm_build_info ALL
    COMMAND ${CMAKE_COMMAND}
        -DOUT=${VESTA_BUILD_INFO_HEADER}
        -DSRC_DIR=${CMAKE_SOURCE_DIR}
        -P ${CMAKE_SOURCE_DIR}/cmake/gen_build_info.cmake
    BYPRODUCTS ${VESTA_BUILD_INFO_HEADER}
    COMMENT "Generando build_info_generated.h (fecha de build + git hash)"
    VERBATIM)
# La dependencia va sobre `vmcore`, que es quien compila version_info.cpp.
# Puesta sobre `vm` no ordenaba nada: el nucleo podia compilar esa unidad ANTES
# de que el header existiera, y entonces `--version` decia "desconocida" -- que
# es un fallo que no rompe el build, solo miente en la salida.
add_dependencies(vmcore vm_build_info)

# Nota: aqui habia exenciones `-fno-fast-math` para los dos ficheros que
# calculan aritmetica del lenguaje (`src/runtime/exec_instruction_float.cpp` y
# `src/ir/ir_optimizer.cpp`).  Sobran desde que `-ffast-math` no se usa en
# ninguna parte -- ver la lista de opciones de Release --, y un flag muerto
# confunde mas de lo que documenta.

# `capstone` NO va aqui: es una libreria de OBJETOS, y CMake mete sus objetos
# DENTRO de `libvmcore.a` al enlazarla contra el.  Ponerla ademas suelta los
# duplicaba (304 simbolos definidos dos veces).
target_link_libraries(vm
        PRIVATE sqlite3
        PRIVATE keystone
        PRIVATE vx_lib
        PRIVATE vesta_toolchain
        PRIVATE aot_emit
)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(vm PRIVATE vpp_lib)

    # copiar include_lib junto al ejecutable para que #import <vesta/...> funcione
    # sin necesidad de instalar ni configurar rutas manualmente
    add_custom_command(TARGET vm POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/preprocessor/include_lib"
            "$<TARGET_FILE_DIR:vm>/include_lib"
        COMMENT "Copiando stdlib vpp (include_lib) al directorio de salida"
    )
endif()

# OpenSSL: vm enlaza el target INTERFACE `vesta_openssl` (definido arriba, antes
# de add_subdirectory(src/vx)).  Estatico (standalone) o FireDaemon segun el
# entorno; un unico punto de verdad para todos los consumidores.
if (WIN32)
    target_link_libraries(vm PRIVATE
            vesta_openssl
            ws2_32           # sockets en Windows
            synchronization  # WaitOnAddress / WakeByAddress* (ThreadPool)
    )
else ()
    target_link_libraries(vm PRIVATE vesta_openssl dl)
endif ()

# LTO (Link Time Optimization)
#set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)

# global
if (WIN32)
target_link_options(vm PRIVATE
        -static
        # Stack reserve 128 MB para el thread principal (donde corre el
        # scheduler single-thread bypass + JIT que aloca buffers grandes
        # via host_alloca, arrays nativos `u8[N]` con N grande, etc).
        # Default Win64 era 1 MB que limita programas con recursion profunda
        # o arrays nativos grandes en stack.  La memoria es VirtualAlloc
        # RESERVE (no commit) -- solo paginas tocadas consumen memoria real.
        -Wl,--stack,134217728   # 128 MB reserve (commit on touch)
)
endif()

# release
target_link_options(vm PRIVATE
        $<$<CONFIG:Release>:

        # --- Eliminación de código muerto ---
        -Wl,--gc-sections          # Elimina funciones/datos no usados

        # --- Reducción de tamaño ---
        -Wl,--strip-all            # Elimina todos los símbolos
        -Wl,--as-needed            # Solo enlaza libs realmente usadas
        -Wl,--build-id=none        # No genera build-id (reduce tamaño)

        # --- Flags NO soportados por tu MinGW (comentados) ---
        #-Wl,--icf=all             # Identical Code Folding (solo gold/lld)
        #-Wl,--compress-debug-sections=zlib   # Solo binutils modernos
        #-flto=thin                # mi MinGW no soporta LTO
        >

        # Profile enlaza como Release SALVO el estripado: `--strip-all` borra
        # justo lo que hace falta para atribuir cada muestra a una funcion.
        # Tampoco se descartan secciones (--gc-sections) para que no desaparezca
        # codigo frio que se quiera ver en el perfil.
        $<$<CONFIG:Profile>:
        -Wl,--as-needed
        -Wl,--build-id=none
        >
)

# Enlace estatico en Profile igual que en Release: el binario tiene que ser el
# mismo programa, no uno que ademas pague saltos a DLLs que Release no paga.
if (WIN32)
    target_link_options(vm PRIVATE
            $<$<CONFIG:Profile>:-static -static-libgcc -static-libstdc++>
    )
endif ()

# Enlace estático solo en Windows + Release
target_link_options(vm PRIVATE
        $<$<AND:$<CONFIG:Release>,$<BOOL:${WIN32}>>:
        # --- Enlace estático ---
        -static                    # Binario autónomo
        -static-libgcc             # Libgcc estática
        -static-libstdc++          # Libstdc++ estática
        >
)

target_link_libraries(vmcore
        PUBLIC vxdbg_lib
        PUBLIC diag_lib
        # El productor de hechos del ASA lee bloques de asm (isa_actual,
        # build_asm_cfg), y eso vive en vx_lib.  La dependencia existia en el
        # codigo pero no estaba declarada, asi que quien enlazaba vmcore ponia
        # vx_lib donde le parecia -- normalmente ANTES, que con archivos
        # estaticos significa que sus simbolos ya no estan disponibles cuando se
        # descubre que hacen falta.  Declararla deja que CMake ordene.
        PUBLIC vx_lib
        PRIVATE sqlite3
        PRIVATE capstone
        PRIVATE keystone
        PRIVATE aot_emit
)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(vmcore PRIVATE vpp_lib)
    # PUBLIC: `main.cpp` tambien compila contra esto, y ahora se compila en el
    # ejecutable, no aqui.  Como PRIVATE, main.cpp veria una version del
    # programa sin preprocesador y el resto del codigo otra con el.
    target_compile_definitions(vmcore PUBLIC VESTA_HAS_PREPROCESSOR=1)
endif()

if (WIN32)
    # ntdll: `util::read_whole_file` abre por NtOpenFile en vez de CreateFileA,
    # que se ahorra la traduccion de la ruta en cada apertura (ver
    # include/util/file_read.h).  Se ENLAZA en vez de resolverse con
    # GetProcAddress para que un simbolo ausente falle al cargar el proceso y no
    # a mitad de una compilacion.
    target_link_libraries(vmcore PRIVATE vesta_openssl ws2_32 synchronization
            ntdll)
else ()
    target_link_libraries(vmcore PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif ()

# ---------------------------------------------------------------------------
# vesta_toolchain: driver de compilacion reutilizable (.vx -> .velb).
#
# Pega el frontend (vx_lib: compile_vx_source/_project) con el back-end de
# ensamblado/linkado (vmcore: run_worker) en una funcion unica que comparten el
# ejecutable `vm`, el servidor `vesta_lsp` (metodos vesta/compile*) y, via el
# LSP, la libreria cliente Python.  Es una libreria aparte porque vx_lib es
# standalone (no puede depender de vmcore) y vmcore no debe depender de vx_lib.
# Como libreria estatica solo necesita los headers para compilar; los simbolos
# de vx_lib/vmcore se resuelven al enlazar el ejecutable final (que ya enlaza
# ambos).
# ---------------------------------------------------------------------------
add_library(vesta_toolchain STATIC
        src/toolchain/toolchain.cpp
        src/toolchain/aot_build.cpp
        src/toolchain/native_backend.cpp)
target_include_directories(vesta_toolchain PRIVATE ${VM_INCLUDES})
target_compile_features(vesta_toolchain PUBLIC cxx_std_17)

# ---------------------------------------------------------------------------
# Las tres se necesitan ENTRE SI, y hay que decirlo.
#
# `vmcore` llama al lector de asm de `vx_lib`; `vx_lib` llama al almacen de
# hechos que vive en `vmcore`; `vesta_toolchain` llama al backend nativo, que
# tambien esta en `vmcore`.  Mientras `vm` se declaraba con todos los objetos
# sueltos en la linea de enlace daba igual: estaban todos disponibles todo el
# rato.  Compilando el nucleo UNA vez, lo que se enlaza son archivos, y un
# archivo solo aporta lo que hiciera falta cuando el enlazador paso por el.
#
# Declarar el ciclo es lo que permite a CMake repetir los archivos hasta que no
# quede nada por resolver.  La alternativa -- volver a poner los objetos sueltos
# -- es lo que costaba compilarlo todo dos veces.
# ---------------------------------------------------------------------------
target_link_libraries(vx_lib PUBLIC vmcore)
target_link_libraries(vesta_toolchain PUBLIC vmcore)

# ---------------------------------------------------------------------------
# vesta_lsp: servidor Language Server Protocol para Vex (Fase 1).
#
# Binario independiente que habla LSP por stdio (JSON-RPC enmarcado por
# Content-Length) y enlaza el core del compilador EN PROCESO para producir
# diagnosticos en vivo.  Reutiliza:
#   - vx_lib  -> compile_vx_source / compile_vx_project + analyze::bigo.
#   - vmcore   -> ir:: (parse_ir_module_cache) + runtime que el frontend
#                 arrastra transitivamente.
#
# El motor de analisis (src/lsp/analysis_engine.cpp) es el punto unico por el
# que pasaran las futuras fases (semantic tokens, hover con Big-O, ver
# IR/bytecode/JIT/AOT, diagramas), reutilizando el CompileResult cacheado.
# ---------------------------------------------------------------------------
add_executable(vesta_lsp
        src/lsp/json_rpc.cpp
        src/lsp/document_store.cpp
        src/lsp/analysis_engine.cpp
        src/lsp/semantic_tokens.cpp
        src/lsp/param_hints.cpp
        src/lsp/symbol_index.cpp
        src/lsp/inspector.cpp
        src/lsp/builtin_docs.cpp
        src/lsp/lsp_server.cpp
        src/lsp/lsp_main.cpp
)
target_include_directories(vesta_lsp PRIVATE ${VM_INCLUDES})
target_link_libraries(vesta_lsp
        PRIVATE vx_lib
        PRIVATE vesta_toolchain
        PRIVATE vmcore
        PRIVATE sqlite3
        PRIVATE capstone
        PRIVATE keystone
        PRIVATE aot_emit
)
if (VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(vesta_lsp PRIVATE vpp_lib)
    target_compile_definitions(vesta_lsp PRIVATE VESTA_HAS_PREPROCESSOR=1)
endif ()
if (WIN32)
    target_link_libraries(vesta_lsp PRIVATE
            vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(vesta_lsp PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Reduccion de tamano del LSP (espejo de `vm`).  Sin esto el .exe pesaba
# ~327MB: el 91% era DWARF de depuracion sin estripar (las libs estaticas
# vendored la emiten por defecto aunque no haya -g).  Con --strip-all +
# --gc-sections baja a ~26MB (-92%).  No afecta -O3.
target_link_options(vesta_lsp PRIVATE
        $<$<CONFIG:Release>:
        -Wl,--gc-sections
        -Wl,--strip-all
        -Wl,--as-needed
        -Wl,--build-id=none
        >
        $<$<AND:$<CONFIG:Release>,$<BOOL:${WIN32}>>:
        -static -static-libgcc -static-libstdc++
        >
)

# Test unitario de la conversion de posiciones byte->UTF-16.  Solo necesita
# document_store.cpp (autocontenido, sin deps del compilador).
add_executable(test_lsp_position_conv
        tests/lsp/test_position_conv.cpp
        src/lsp/document_store.cpp
)
target_include_directories(test_lsp_position_conv PRIVATE ${VM_INCLUDES})

# Inc 0 de libvesta_gc (GC opt-in de AOT): valida la C-ABI del GcHeap global
# sin ProcessVM.  Linka vmcore (el motor GC vive en src/vesta_gc/, globbeado).
# libvesta_gc: el motor GC (mismo que interp/JIT) empaquetado STANDALONE como
# libreria estatica enlazable en ejecutables AOT que usan gc<T>.  Set minimo:
# gc_lib (C-ABI) + gc_heap + arena + jit_registry/stack_scan (frames precisos).
# Inc 0b dejo gc_heap.cpp sin dependencia de ProcessVM -> esto compila sin la VM.
add_library(vesta_gc STATIC
        src/vesta_gc/gc_lib.cpp
        src/vesta_gc/freestanding_shim.cpp
        src/gc/gc_heap.cpp
        src/gc/wait_table.cpp
        src/gc/shared_handle_table.cpp
        src/arena/arena_manager.cpp
        src/arena/VirtualMemory.cpp
        src/arena/TLB.cpp
        src/jit/jit_registry.cpp
        src/jit/stack_scan.cpp
)
target_include_directories(vesta_gc PUBLIC ${VM_INCLUDES})
# Freestanding-ish: reducir las dependencias de libstdc++ para que el .a se
# enlace SIN g++ (solo libc, que el AOT ya resuelve via IAT/PLT).  -fno-exceptions
# /-rtti/-threadsafe-statics quitan _Unwind/__cxa_*/guards; el define apaga el
# logging GC (std::ostringstream/cerr).  Lo que quede de libstdc++ (operator
# new/delete, unordered_map) se cubre con el shim libvesta_gc_shim.
target_compile_options(vesta_gc PRIVATE
        -fno-exceptions -fno-rtti -fno-threadsafe-statics
        # -g1: simbolos de depuracion minimos (linea + funcion) sobre el -O3
        # heredado de Release, por si hay que depurar el GC en un binario AOT.
        -g1)
target_compile_definitions(vesta_gc PRIVATE
        VESTA_GC_DEBUG_DISABLE=1 VESTA_GC_FREESTANDING=1)

# ---------------------------------------------------------------------------
# Variantes ESTATICAS de los plugins de stdlib (colecciones / math) para AOT
# STANDALONE.  Mismo .c que la DLL, pero VESTA_PLUGIN_EXPORT vacio (sin
# dllexport): el AOT enlaza estos .a (libvesta_collections.a / libvesta_math.a)
# en vez de importar la DLL cuando el programa usa colecciones/math, produciendo
# un .exe sin DLLs.  Solo se enlazan si el programa las usa (auto-link en main).
# -ffunction-sections + -fdata-sections para que el linker descarte lo no usado.
add_library(vesta_collections_a STATIC
        stdlib/native/collections/vesta_collections.c)
set_target_properties(vesta_collections_a PROPERTIES
        OUTPUT_NAME vesta_collections C_STANDARD 11)
target_include_directories(vesta_collections_a PRIVATE
        ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(vesta_collections_a PRIVATE "VESTA_PLUGIN_EXPORT=")
# -O3 (heredado de Release) para codigo optimo + -g1 para conservar simbolos de
# depuracion MINIMOS (tablas de linea + nombres de funcion): suficiente para
# backtraces / addr2line / gdb, sin el peso de -g2/-g3 (variables locales, macros).
target_compile_options(vesta_collections_a PRIVATE
        -ffunction-sections -fdata-sections -g1)

add_library(vesta_math_a STATIC stdlib/native/math/vesta_math.c)
set_target_properties(vesta_math_a PROPERTIES
        OUTPUT_NAME vesta_math C_STANDARD 11)
target_include_directories(vesta_math_a PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(vesta_math_a PRIVATE "VESTA_PLUGIN_EXPORT=")
target_compile_options(vesta_math_a PRIVATE
        -ffunction-sections -fdata-sections -g1)

add_executable(test_gc_lib tests/gc/test_gc_lib.cpp)
target_include_directories(test_gc_lib PRIVATE ${VM_INCLUDES})
# vmcore es STATIC y sus deps son PRIVATE -> replicar el set de enlace.
target_link_libraries(test_gc_lib PRIVATE vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_gc_lib PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_gc_lib PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_gc_lib PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Reconocer un builtin por su nombre.  El orden de la tabla y que cuadre con
# el enum los comprueba el compilador; esto comprueba lo que no puede: que la
# busqueda encuentra cada nombre, y que NO encuentra los que se le parecen.
add_executable(test_vx_builtin_names tests/vx/test_vx_builtin_names.cpp)
target_include_directories(test_vx_builtin_names PRIVATE ${VM_INCLUDES})
target_link_libraries(test_vx_builtin_names PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_vx_builtin_names PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_vx_builtin_names PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_vx_builtin_names PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Driver incremental granular (claves Merkle + CAS + plan_rebuild + fragmentos
# de IR).  vx_lib aporta el indice + el driver; vmcore aporta ir:: (IrModule,
# serializacion).  vx_lib va PRIMERO: referencia simbolos ir:: de vmcore.
add_executable(test_vx_incremental tests/vx/test_incremental.cpp)
target_include_directories(test_vx_incremental PRIVATE ${VM_INCLUDES})
target_link_libraries(test_vx_incremental PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_vx_incremental PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_vx_incremental PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_vx_incremental PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Huella computacional por-funcion (recursos + efectos + composicion).
add_executable(test_analyze_fingerprint tests/analyze/test_fingerprint.cpp)
target_include_directories(test_analyze_fingerprint PRIVATE ${VM_INCLUDES})
target_link_libraries(test_analyze_fingerprint PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_analyze_fingerprint PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_analyze_fingerprint PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_analyze_fingerprint PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Infra de analisis: AnalysisManager (type-erasure + dependencias + invalidacion).
add_executable(test_analysis_manager tests/analysis/test_manager.cpp)
target_include_directories(test_analysis_manager PRIVATE ${VM_INCLUDES})

# Coste por opcode derivado del codigo maquina de los handlers.  ENLAZA la VM
# a proposito: asi las tablas de decodificacion son datos de este proceso y los
# campos `exec`/`decode` son direcciones ya mapeadas, sin resolver simbolos ni
# parsear PE/ELF.  No toca el interprete: mide desde fuera lo ya compilado.
add_executable(test_coste_opcodes tests/coste/test_coste_opcodes.cpp)
target_include_directories(test_coste_opcodes PRIVATE ${VM_INCLUDES})
target_link_libraries(test_coste_opcodes PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_coste_opcodes PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_coste_opcodes PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_coste_opcodes PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# ¿Se pisan las instrucciones de un bucle en la icache?  Simulacion ESTATICA
# sobre el `.velb`: no ejecuta la VM y no la toca.  Contesta si el coste de
# redescodificar se paga una vez o en cada vuelta, que es lo que decide si
# merece la pena cambiar el indice de la icache.
add_executable(test_icache_conflictos tests/coste/test_icache_conflictos.cpp)
target_include_directories(test_icache_conflictos PRIVATE ${VM_INCLUDES})
target_link_libraries(test_icache_conflictos PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_icache_conflictos PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_icache_conflictos PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_icache_conflictos PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()
add_executable(test_icache_real tests/coste/test_icache_real.cpp)
target_include_directories(test_icache_real PRIVATE ${VM_INCLUDES})
target_link_libraries(test_icache_real PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_icache_real PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_icache_real PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_icache_real PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()



# Sistema unico de efectos: reticulo AbstractLoc, combinadores seq/join,
# contratos declarativos.
add_executable(test_effects tests/effects/test_effects.cpp)
target_include_directories(test_effects PRIVATE ${VM_INCLUDES})
target_link_libraries(test_effects PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_effects PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_effects PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_effects PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Modelo de memoria UNICO: alias por rangos (may/must/no) + resolvedor
# points-to compartido (raiz + offset const).
# Motor de rangos: dominio (reticulo + aritmetica sin desbordar) y flujo
# (guardas, ramas imposibles, PHI por arista, terminacion de bucles).
add_executable(test_value_range tests/analysis/test_value_range.cpp)
target_include_directories(test_value_range PRIVATE ${VM_INCLUDES})
target_link_libraries(test_value_range PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_value_range PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_value_range PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_value_range PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Bateria de FORMAS DE USO: el mismo esqueleto tiene que dar el mismo
# conocimiento, y la explicacion tiene que ser tan correcta como el veredicto.
add_executable(test_aggregate_facts tests/analysis/test_aggregate_facts.cpp)
target_include_directories(test_aggregate_facts PRIVATE ${VM_INCLUDES})
target_link_libraries(test_aggregate_facts PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_aggregate_facts PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_aggregate_facts PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_aggregate_facts PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Resumenes de frontera: que entra y que sale de una funcion, y cuando se puede
# afirmar (mundo cerrado, punteros a funcion resueltos, recursion).
add_executable(test_range_summary tests/analysis/test_range_summary.cpp)
target_include_directories(test_range_summary PRIVATE ${VM_INCLUDES})
target_link_libraries(test_range_summary PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_range_summary PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_range_summary PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_range_summary PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Round-trip del serializador del IR.  Importa que este DECLARADO: el AOT
# compila desde el IR serializado, asi que lo que no cruce esta frontera no
# existe para el -- y un test que nadie compila no avisa de nada.
# El coalescing pregunta por su OBJETIVO en vez de suponerlo: la restriccion de
# dos direcciones solo existe donde la ALU destruye el destino.
add_executable(test_ssa_coalesce_target tests/jit/test_ssa_coalesce_target.cpp)
target_include_directories(test_ssa_coalesce_target PRIVATE ${VM_INCLUDES})
target_link_libraries(test_ssa_coalesce_target PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_ssa_coalesce_target PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_ssa_coalesce_target PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_ssa_coalesce_target PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Vocabulario UNICO de propiedades de un IrType (tres ejes de anchura + clase).
# Los oraculos del test son copias literales de las doce tablas que sustituye:
# es lo que demuestra que la migracion no cambia comportamiento.
add_executable(test_ir_type_info tests/ir/test_ir_type_info.cpp)
target_include_directories(test_ir_type_info PRIVATE ${VM_INCLUDES})
target_link_libraries(test_ir_type_info PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_ir_type_info PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_ir_type_info PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_ir_type_info PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_ir_serialize tests/ir/test_ir_serialize.cpp)
target_include_directories(test_ir_serialize PRIVATE ${VM_INCLUDES})
target_link_libraries(test_ir_serialize PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_ir_serialize PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_ir_serialize PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_ir_serialize PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Recorrido de un arbol de fuentes usando lo que el listado del sistema ya
# devuelve.  Es solo cabecera, asi que no necesita enlazar nada del proyecto.
add_executable(test_recorrer_arbol tests/util/test_recorrer_arbol.cpp)
target_include_directories(test_recorrer_arbol PRIVATE ${VM_INCLUDES})

# La huella de lo que un consumidor VE de un modulo importado.
add_executable(test_vxi_hash_simbolos tests/vx/test_vxi_hash_simbolos.cpp)
target_include_directories(test_vxi_hash_simbolos PRIVATE ${VM_INCLUDES})
target_link_libraries(test_vxi_hash_simbolos PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_vxi_hash_simbolos PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_vxi_hash_simbolos PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_vxi_hash_simbolos PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# La identidad de un fuente para la cache: lo que dice, no como esta escrito.
add_executable(test_source_hash tests/vx/test_source_hash.cpp)
target_include_directories(test_source_hash PRIVATE ${VM_INCLUDES})
target_link_libraries(test_source_hash PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_source_hash PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_source_hash PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_source_hash PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Puente entre el texto de un asm y los valores del programa (de que valor habla
# cada operando), ancho aportado por la CLASE del operando, y universo bajo el
# que se resume una funcion (artefacto + visibilidad).
add_executable(test_asm_bindings tests/analysis/test_asm_bindings.cpp)
target_include_directories(test_asm_bindings PRIVATE ${VM_INCLUDES})
target_link_libraries(test_asm_bindings PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_asm_bindings PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_asm_bindings PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_asm_bindings PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_mem_loc tests/analysis/test_mem_loc.cpp)
target_include_directories(test_mem_loc PRIVATE ${VM_INCLUDES})
target_link_libraries(test_mem_loc PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_mem_loc PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_mem_loc PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_mem_loc PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# DB de instrucciones embebida: matcher texto->FormID.
add_executable(test_instr_db tests/vx/instr_db_test.cpp)
target_include_directories(test_instr_db PRIVATE ${VM_INCLUDES})
target_link_libraries(test_instr_db PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_instr_db PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_instr_db PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_instr_db PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# CFG del asm inline (bloques basicos + aristas).
add_executable(test_asm_cfg tests/vx/asm_cfg_test.cpp)
target_include_directories(test_asm_cfg PRIVATE ${VM_INCLUDES})
target_link_libraries(test_asm_cfg PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_asm_cfg PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_asm_cfg PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_asm_cfg PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Diagnosticos estructurales del asm sobre el CFG.
add_executable(test_asm_diag tests/vx/asm_diag_test.cpp)
target_include_directories(test_asm_diag PRIVATE ${VM_INCLUDES})
target_link_libraries(test_asm_diag PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_asm_diag PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_asm_diag PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_asm_diag PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Diagramas del CFG del asm anotados con coste.
add_executable(test_asm_diagram tests/vx/asm_diagram_test.cpp)
target_include_directories(test_asm_diagram PRIVATE ${VM_INCLUDES})
target_link_libraries(test_asm_diagram PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_asm_diagram PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_asm_diagram PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_asm_diagram PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Lift de patrones de asm a IR tipado (atomicos).
add_executable(test_asm_lift tests/vx/asm_lift_test.cpp)
target_include_directories(test_asm_lift PRIVATE ${VM_INCLUDES})
target_link_libraries(test_asm_lift PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_asm_lift PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_asm_lift PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_asm_lift PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Catalogo multi-idioma de diagnosticos.
add_executable(test_diag_catalog tests/vx/diag_catalog_test.cpp)
target_include_directories(test_diag_catalog PRIVATE ${VM_INCLUDES})
target_link_libraries(test_diag_catalog PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_diag_catalog PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_diag_catalog PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_diag_catalog PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Selector IR -> AArch64 (backend arm64, Phase H.2).
add_executable(test_arm64_select tests/jit/test_arm64_select.cpp)
target_include_directories(test_arm64_select PRIVATE ${VM_INCLUDES})
target_link_libraries(test_arm64_select PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_arm64_select PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_arm64_select PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_arm64_select PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Banco de registros fisico unico (allocator de banco ancho, Fase 0):
# consolidacion de TargetRegInfo + BackendCaps en un modelo comun (Lane/View/
# SavePolicy/AliasSet/Reserve).  Test de round-trip contra los targets.
# Subsistema de depuracion (vxdbg): identidad por contenido y capacidades.
# No enlaza con el resto del compilador a proposito -- el subsistema esta
# pensado para ser reutilizable por cualquier frontend, y si su test necesitara
# media maquina virtual para arrancar es que esa independencia no seria cierta.
add_executable(test_vxdbg_core tests/vxdbg/test_vxdbg_core.cpp
                               src/vxdbg/ids.cpp
                               src/vxdbg/capabilities.cpp)
target_include_directories(test_vxdbg_core PRIVATE ${VM_INCLUDES})

# Serializacion y almacen por contenido: el mismo juego de pruebas se pasa al
# almacen de memoria y al de disco, porque si no se comportaran igual, probar
# contra uno no diria nada del otro.
# `file_read` y `env_flags` no estaban, y en Windows no se notaba: alli el
# almacen en disco toma otro camino y no llega a referenciar `DirectoryReader`
# ni `read_whole_file`.  En Linux si, y el test no enlazaba -- rompiendo el
# objetivo `all`, del que cuelga el paso previo de CPack: el instalador no se
# podia ni generar por culpa de un test.
add_executable(test_vxdbg_store tests/vxdbg/test_vxdbg_store.cpp
                                src/vxdbg/ids.cpp
                                src/util/serialize.cpp
                                src/util/file_read.cpp
                                src/util/env_flags.cpp
                                src/vxdbg/store.cpp
                                src/vxdbg/pack_store.cpp)
target_include_directories(test_vxdbg_store PRIVATE ${VM_INCLUDES})
if (WIN32)
    # Y por la MISMA razon de arriba hace falta ntdll: `read_whole_file` abre
    # por NtOpenFile, asi que quien compile ese fichero tiene que enlazarlo.
    # El objetivo principal ya lo hacia; este se quedo fuera y volvia a romper
    # `all` -- con ello el instalador -- por un test.
    target_link_libraries(test_vxdbg_store PRIVATE ntdll)
endif ()

# Serializacion de cada nodo.  Comprueba, sobre todo, que la identidad de un
# nodo ES su serializacion: si dos iguales dieran huellas distintas no se
# reutilizaria nada, y si dos distintos dieran la misma el almacen serviria uno
# por otro.
add_executable(test_vxdbg_codec tests/vxdbg/test_vxdbg_codec.cpp
                                src/vxdbg/ids.cpp
                                src/util/serialize.cpp
                                src/vxdbg/store.cpp
                                src/vxdbg/lowering_map.cpp
                                src/vxdbg/codec_source.cpp
                                src/vxdbg/codec_backend.cpp
                                src/vxdbg/semantic_resolve.cpp
                                src/vxdbg/roots.cpp)
target_include_directories(test_vxdbg_codec PRIVATE ${VM_INCLUDES} src/vxdbg)

# El recorrido completo: de una direccion a una explicacion.  Cada capa esta
# probada por su cuenta, pero eso no dice si el camino entero funciona -- es
# justo donde se ven los desajustes entre piezas que por separado estan bien.
# El unico que enlaza con el frontend: comprueba que lo que el compilador SABE
# cabe en el modelo, cosa que un grafo escrito a mano nunca puede demostrar.
add_executable(test_vxdbg_frontend tests/vxdbg/test_vxdbg_frontend.cpp)
target_include_directories(test_vxdbg_frontend PRIVATE ${VM_INCLUDES})
# Enlaza tambien vmcore porque el checker puede ejecutar codigo comptime, y eso
# necesita la maquina virtual entera.  Los otros tests del subsistema NO enlazan
# nada de esto: son la prueba de que vxdbg no depende del compilador.
# vx_lib aparece dos veces a proposito: las dos librerias se necesitan
# mutuamente y el enlazador recorre la lista una sola vez.
target_link_libraries(test_vxdbg_frontend PRIVATE vx_lib vmcore vx_lib
        vesta_openssl)
set_target_properties(test_vxdbg_frontend PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_vxdbg_resolve tests/vxdbg/test_vxdbg_resolve.cpp
                                  src/vxdbg/ids.cpp
                                  src/util/serialize.cpp
                                  src/vxdbg/store.cpp
                                  src/vxdbg/lowering_map.cpp
                                  src/vxdbg/backend_meta.cpp
                                  src/vxdbg/codec_source.cpp
                                  src/vxdbg/codec_backend.cpp
                                  src/vxdbg/store_source.cpp
                                  src/vxdbg/resolver.cpp)
target_include_directories(test_vxdbg_resolve PRIVATE ${VM_INCLUDES} src/vxdbg)

add_executable(test_rbank_physical tests/jit/test_rbank_physical.cpp)
target_include_directories(test_rbank_physical PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_physical PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_physical PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_physical PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_physical PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# ValueRequirements (banco ancho, Fase 0 nivel 1): que necesita un valor +
# satisfacibilidad contra el banco fisico (motivos como DATO i18n-ready).
add_executable(test_rbank_value_req tests/jit/test_rbank_value_req.cpp)
target_include_directories(test_rbank_value_req PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_value_req PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_value_req PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_value_req PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_value_req PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Constraints (banco ancho, Fase 0 nivel 2): feasibilidad DURA + verificador de
# soluciones (validate_assignment), con violaciones como DATO i18n-ready.
add_executable(test_rbank_constraints tests/jit/test_rbank_constraints.cpp)
target_include_directories(test_rbank_constraints PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_constraints PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_constraints PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_constraints PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_constraints PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Objective (banco ancho, Fase 0 nivel 3): framework de scoring SUAVE +
# estimadores (spill/callsave/move) que interpretan los hechos como preferencias.
add_executable(test_rbank_objective tests/jit/test_rbank_objective.cpp)
target_include_directories(test_rbank_objective PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_objective PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_objective PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_objective PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_objective PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# OptimizationContext + DecisionPolicy (banco ancho, Fase 0 cuspide): firma
# estable + seleccion determinista (Predictor hook), con explicacion como DATO.
add_executable(test_rbank_decision tests/jit/test_rbank_decision.cpp)
target_include_directories(test_rbank_decision PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_decision PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_decision PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_decision PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_decision PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# TypeAdapter (banco ancho, Fase 0.25): IrType -> clase + width.  Primer
# adaptador (solo traduce, no inventa logica); reusa memory_access_size.
add_executable(test_rbank_type_adapter tests/jit/test_rbank_type_adapter.cpp)
target_include_directories(test_rbank_type_adapter PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_type_adapter PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_type_adapter PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_type_adapter PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_type_adapter PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# LivenessAdapter (Fase 0.25): liveness + call positions -> crosses_call.
# Integracion con compute_liveness real (valida linealizacion consistente).
add_executable(test_rbank_liveness_adapter tests/jit/test_rbank_liveness_adapter.cpp)
target_include_directories(test_rbank_liveness_adapter PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_liveness_adapter PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_liveness_adapter PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_liveness_adapter PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_liveness_adapter PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# ConstAdapter (Fase 0.25): is_const -> rematerializable.
add_executable(test_rbank_const_adapter tests/jit/test_rbank_const_adapter.cpp)
target_include_directories(test_rbank_const_adapter PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_const_adapter PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_const_adapter PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_const_adapter PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_const_adapter PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# LoopFacts (analysis) + LoopAdapter (banco ancho, Fase 0.25.4): deteccion de
# bucles unificada (profundidad/header/parent) + adaptador loop_depth.
add_executable(test_loop_facts tests/analysis/test_loop_facts.cpp)
target_include_directories(test_loop_facts PRIVATE ${VM_INCLUDES})
target_link_libraries(test_loop_facts PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_loop_facts PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_loop_facts PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_loop_facts PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_rbank_loop_adapter tests/jit/test_rbank_loop_adapter.cpp)
target_include_directories(test_rbank_loop_adapter PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_loop_adapter PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_loop_adapter PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_loop_adapter PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_loop_adapter PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# ProfileFacts (analysis/derived, fact Tipo B) + ProfileAdapter (banco ancho):
# perfil centralizado -> trip-count/peso por bloque + adaptador execution_weight.
add_executable(test_profile_facts tests/analysis/test_profile_facts.cpp)
target_include_directories(test_profile_facts PRIVATE ${VM_INCLUDES})
target_link_libraries(test_profile_facts PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_profile_facts PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_profile_facts PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_profile_facts PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_rbank_profile_adapter tests/jit/test_rbank_profile_adapter.cpp)
target_include_directories(test_rbank_profile_adapter PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_profile_adapter PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_profile_adapter PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_profile_adapter PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_profile_adapter PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# build_value_requirements (snapshot vivo) + auditor: corre los adaptadores sobre
# una funcion real y detecta valores imposibles.
add_executable(test_rbank_build tests/jit/test_rbank_build.cpp)
target_include_directories(test_rbank_build PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_build PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_build PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_build PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_build PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# FunctionSnapshot (codegen/rbank): fotografia del conocimiento del compilador
# sobre una funcion (Facts + ValueRequirements) + autocertificacion agregada.
add_executable(test_rbank_snapshot tests/jit/test_rbank_snapshot.cpp)
target_include_directories(test_rbank_snapshot PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_snapshot PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_snapshot PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_snapshot PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_snapshot PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_rbank_roundtrip tests/jit/test_rbank_roundtrip.cpp)
target_include_directories(test_rbank_roundtrip PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_roundtrip PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_roundtrip PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_roundtrip PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_roundtrip PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_rbank_canonical tests/jit/test_rbank_canonical.cpp)
target_include_directories(test_rbank_canonical PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_canonical PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_canonical PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_canonical PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_canonical PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_rbank_shadow tests/jit/test_rbank_shadow.cpp)
target_include_directories(test_rbank_shadow PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_shadow PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_shadow PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_shadow PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_shadow PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_rbank_smart_spill tests/jit/test_rbank_smart_spill.cpp)
target_include_directories(test_rbank_smart_spill PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_smart_spill PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_smart_spill PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_smart_spill PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_smart_spill PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_rbank_crosscall tests/jit/test_rbank_crosscall.cpp)
target_include_directories(test_rbank_crosscall PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_crosscall PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_crosscall PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_crosscall PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_crosscall PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_rbank_bridge tests/jit/test_rbank_bridge.cpp)
target_include_directories(test_rbank_bridge PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_bridge PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_bridge PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_bridge PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_bridge PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_remat_facts tests/jit/test_remat_facts.cpp)
target_include_directories(test_remat_facts PRIVATE ${VM_INCLUDES})
target_link_libraries(test_remat_facts PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_remat_facts PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_remat_facts PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_remat_facts PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_use_def_facts tests/jit/test_use_def_facts.cpp)
target_include_directories(test_use_def_facts PRIVATE ${VM_INCLUDES})
target_link_libraries(test_use_def_facts PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_use_def_facts PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_use_def_facts PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_use_def_facts PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# El ALCANCE de un hecho: quien lo ve y quien no.  Su forma de fallar no es un
# resultado equivocado, es SILENCIO -- y el silencio no se distingue de "no se
# sabe" --, asi que hace falta un test que lo exija.
add_executable(test_asa_ambito tests/analysis/test_asa_ambito.cpp)
target_include_directories(test_asa_ambito PRIVATE ${VM_INCLUDES})
target_link_libraries(test_asa_ambito PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)

# Que un analisis que no sabe algo diga POR QUE, y que las dos clases de "no
# se" -- depende de la ejecucion / el analisis no cubre esa forma -- no se
# confundan: de esa diferencia depende que el consumidor especule o se rinda.
add_executable(test_trip_count_reason tests/analysis/test_trip_count_reason.cpp)
target_include_directories(test_trip_count_reason PRIVATE ${VM_INCLUDES})
target_link_libraries(test_trip_count_reason PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)

# Que lo DECLARADO de una funcion externa cuente, y -- lo que mas importa --
# que lo NO declarado siga siendo conservador.
add_executable(test_native_effects tests/analyze/test_native_effects.cpp)
target_include_directories(test_native_effects PRIVATE ${VM_INCLUDES})
target_link_libraries(test_native_effects PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)

# Que ningun veredicto de contrato se descarte en silencio, y que los codigos
# del linter existan en los dos idiomas.
add_executable(test_lint_contracts tests/analyze/test_lint_contracts.cpp)
target_include_directories(test_lint_contracts PRIVATE ${VM_INCLUDES})
target_link_libraries(test_lint_contracts PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)

add_executable(test_asa_fact_store tests/analysis/test_asa_fact_store.cpp)
target_include_directories(test_asa_fact_store PRIVATE ${VM_INCLUDES})
target_link_libraries(test_asa_fact_store PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_asa_fact_store PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_asa_fact_store PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_asa_fact_store PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_asa_fact_file tests/analysis/test_asa_fact_file.cpp)
target_include_directories(test_asa_fact_file PRIVATE ${VM_INCLUDES})
target_link_libraries(test_asa_fact_file PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_asa_fact_file PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_asa_fact_file PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_asa_fact_file PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Suelto a proposito: cuatro ficheros y nada del compilador, para poder
# correrlo en un sistema donde el proyecto entero no este construido -- que es
# justo el caso al comprobar que el formato cruza de plataforma.
# Suelto y sin dependencias: el cronometro no depende de nada del compilador, y
# poder probarlo aparte es parte de que sea reutilizable.
add_executable(test_crono_precision tests/util/test_crono_precision.cpp
                                    src/util/crono_tramo.cpp
                                    src/util/reloj.cpp)
target_include_directories(test_crono_precision PRIVATE ${VM_INCLUDES})
if (NOT WIN32)
    target_link_libraries(test_crono_precision PRIVATE pthread)
endif ()

add_executable(test_locset_indice tests/analysis/test_locset_indice.cpp
                                  src/analysis/effects/effects.cpp)
target_include_directories(test_locset_indice PRIVATE ${VM_INCLUDES})

# `env_flags` da `flag_text`, que el fichero de hechos usa para nombrar cada
# bandera.  Faltaba, y como el otro test del almacen, solo se notaba en Linux.
add_executable(test_asa_fact_file_lnx tests/analysis/test_asa_fact_file_lnx.cpp
                                      src/analysis/asa/fact_file.cpp
                                      src/analysis/asa/fact_store.cpp
                                      src/util/env_flags.cpp
                                      src/util/serialize.cpp)
target_include_directories(test_asa_fact_file_lnx PRIVATE ${VM_INCLUDES})

add_executable(test_asa_fact_file_robusto tests/analysis/test_asa_fact_file_robusto.cpp)
target_include_directories(test_asa_fact_file_robusto PRIVATE ${VM_INCLUDES})
target_link_libraries(test_asa_fact_file_robusto PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_asa_fact_file_robusto PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_asa_fact_file_robusto PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_asa_fact_file_robusto PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# Liveness por registro FISICO: que sigue vivo tras cada instruccion del
# MachineIR ya repartido.  Comprueba lo que NO se ve en los operandos (el
# RDX:RAX de una division, la base de una direccion, los registros de un asm).
add_executable(test_jit_phys_liveness tests/jit/test_phys_liveness.cpp)
target_include_directories(test_jit_phys_liveness PRIVATE ${VM_INCLUDES})
target_link_libraries(test_jit_phys_liveness PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)

add_executable(test_jit_facts tests/jit/test_jit_facts.cpp)
target_include_directories(test_jit_facts PRIVATE ${VM_INCLUDES})
target_link_libraries(test_jit_facts PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_jit_facts PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_jit_facts PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_jit_facts PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_next_use tests/jit/test_next_use.cpp)
target_include_directories(test_next_use PRIVATE ${VM_INCLUDES})
target_link_libraries(test_next_use PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_next_use PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_next_use PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_next_use PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_rbank_coalesce tests/jit/test_rbank_coalesce.cpp)
target_include_directories(test_rbank_coalesce PRIVATE ${VM_INCLUDES})
target_link_libraries(test_rbank_coalesce PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_rbank_coalesce PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_rbank_coalesce PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_rbank_coalesce PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_vec_acc_demand tests/jit/test_vec_acc_demand.cpp)
target_include_directories(test_vec_acc_demand PRIVATE ${VM_INCLUDES})
target_link_libraries(test_vec_acc_demand PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_vec_acc_demand PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_vec_acc_demand PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_vec_acc_demand PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

add_executable(test_machine_cost_facts tests/jit/test_machine_cost_facts.cpp)
target_include_directories(test_machine_cost_facts PRIVATE ${VM_INCLUDES})
target_link_libraries(test_machine_cost_facts PRIVATE vx_lib vmcore sqlite3 capstone keystone aot_emit)
if(VESTA_BUILD_PREPROCESSOR)
    target_link_libraries(test_machine_cost_facts PRIVATE vpp_lib)
endif()
if (WIN32)
    target_link_libraries(test_machine_cost_facts PRIVATE vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(test_machine_cost_facts PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
endif ()

# ---------------------------------------------------------------------------
# libvesta: DLL/.so con C-ABI estable para embeber VestaVM en cualquier
# lenguaje (Python via ctypes, Rust FFI, C#, C, ...).  Expone
# vesta_compile / vesta_run / vesta_eval / vesta_version / vesta_free.
#
# Se construye a partir del MISMO conjunto de fuentes del ejecutable `vm`
# (VM_SOURCES) PERO sin main.cpp (un main() en una libreria compartida no
# tiene sentido y colisiona con el CRT) + el wrapper C de la API.  Enlaza
# exactamente las mismas dependencias que el target `vm`.
# ---------------------------------------------------------------------------
option(VESTA_BUILD_FFI "Construir libvesta (DLL/.so con C-ABI)" ON)
if (VESTA_BUILD_FFI)
    # Lista de fuentes = VM_SOURCES menos main.cpp (no queremos un entry
    # point en la libreria compartida).
    # La DLL es la API C sobre el MISMO nucleo, no otra copia de el.
    #
    # Antes se declaraba con todas las fuentes de la maquina dentro, o sea que
    # las compilaba enteras por tercera vez (el 18,5% del build).  Y compilaba
    # exactamente lo mismo: `VESTA_BUILD_DLL` solo lo mira la cabecera publica de
    # `src/capi/`, que es la unica fuente que queda aqui.
    add_library(vesta_ffi SHARED
            ${CMAKE_CURRENT_SOURCE_DIR}/src/capi/vesta_capi.cpp
    )

    # OUTPUT_NAME "vesta" -> vesta.dll (Windows) / libvesta.so (POSIX).
    set_target_properties(vesta_ffi PROPERTIES OUTPUT_NAME "vesta")

    # VESTA_BUILD_DLL activa __declspec(dllexport) en la cabecera publica.
    target_compile_definitions(vesta_ffi PRIVATE VESTA_BUILD_DLL)

    # (exec_instruction_float.cpp ya no se compila aqui: viene de `vmcore`, que
    # es donde esta el override de IEEE estricto.)

    target_include_directories(vesta_ffi PRIVATE ${VM_INCLUDES})

    target_link_libraries(vesta_ffi
            # Archivo COMPLETO, por lo mismo que en `vm`: hay unidades que solo
            # se registran solas al arrancar y a las que nadie llama por nombre.
            PRIVATE $<LINK_LIBRARY:WHOLE_ARCHIVE,vmcore>
            PRIVATE sqlite3
            PRIVATE keystone   # capstone llega dentro de vmcore (ver `vm`)
            PRIVATE vx_lib
            PRIVATE aot_emit
    )
    if (VESTA_BUILD_PREPROCESSOR)
        target_link_libraries(vesta_ffi PRIVATE vpp_lib)
        target_compile_definitions(vesta_ffi PRIVATE VESTA_HAS_PREPROCESSOR=1)
    endif ()

    if (WIN32)
        target_link_libraries(vesta_ffi PRIVATE
                vesta_openssl ws2_32 synchronization)
        # DLL autocontenido: enlazar TODO estaticamente (libgcc, libstdc++ y
        # libwinpthread via -static, mas OpenSSL via vesta_openssl) para que el
        # consumidor de vesta.dll no necesite NINGUN runtime DLL adicional de
        # MinGW ni de OpenSSL.  Sin -static (solo -static-libgcc/-libstdc++),
        # libwinpthread-1.dll quedaba como dependencia dinamica -> el consumidor
        # fallaba con "no se encuentra el punto de entrada clock_gettime64" en un
        # sistema con un libwinpthread distinto.
        target_link_options(vesta_ffi PRIVATE
                -static -static-libgcc -static-libstdc++)
    else ()
        target_link_libraries(vesta_ffi PRIVATE OpenSSL::SSL OpenSSL::Crypto dl)
    endif ()

    # Auto-build opt-in: por defecto `cmake --build . --target vm` produce SOLO
    # el ejecutable (iteracion rapida: un solo enlace).  Con -DVESTA_VM_BUILDS_FFI=ON
    # tambien arrastra libvesta.dll/.so.  Para construir la DLL a demanda:
    # `cmake --build . --target vesta_ffi`.
    option(VESTA_VM_BUILDS_FFI "Construir libvesta junto al ejecutable vm" OFF)
    if (VESTA_VM_BUILDS_FFI)
        add_dependencies(vm vesta_ffi)
    endif ()
endif ()

# ---------------------------------------------------------------------------
# Mejora III: libvesta_rt como libreria independiente.
#
# Subset estricto de @c vmcore que contiene SOLO los componentes del runtime
# puro (GC, scheduler, mailbox, futures, monitores, FFI, class_registry,
# arena, distribucion VDP).  No incluye:
#   - frontend del lenguaje (vx, ir, lexer, parser, emmit)
#   - linker / loader principal del .velb (solo class_registry)
#   - CLI / VSH / REPL
#   - jit, optimizer, profiler, install
#
# Objetivo: el codigo JIT-eado o AOT-compilado en fases futuras 
# podra enlazar contra vesta_rt sin arrastrar el frontend.  Mismo binary
# layout y misma calling convention que las funciones de runtime que el
# bytecode invoca via CALLN.
#
# Estado: MVP -- la libreria compila independientemente y expone los
# simbolos del runtime.  El target @c vm sigue compilando monoliticamente
# todo (sin regresion).  Una integracion mas profunda (vm enlazado contra
# vesta_rt + romper circular loader.h <-> runtime.h) queda para Phase C
# del roadmap, donde se desacople tambien el loader.
# ---------------------------------------------------------------------------
set(VESTA_RT_SOURCES
        # GC - heap generacional + raw allocator
        ${CMAKE_CURRENT_SOURCE_DIR}/src/gc/gc_heap.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/gc/raw_allocator.cpp

        # Arena manager - VirtualMemory + TLB + ArenaManager
        ${CMAKE_CURRENT_SOURCE_DIR}/src/arena/VirtualMemory.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/arena/TLB.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/arena/arena_manager.cpp

        # Runtime core - ProcessVM + Scheduler + ManageVM + decoder/exec
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/proceso_runtime.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/runtime.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/scheduler.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/manager_runtime.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/decode_instruction.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/decode_table.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exception_runtime.cpp

        # Runtime - exec instructions (todas las familias del set)
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_alu.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_gc.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_oop.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_closure.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_pattern.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_async.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_spimm.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_weak.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_sync.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_generic.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_distrib.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_exc.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_string.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_meta.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_coro.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/exec_instruction_float.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/host_alloca_tracker.cpp
        # Sprint D.6 (2026-06-03): profile counters runtime para PGO + C2.
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/profile.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/native_callback.cpp

        # Distribucion - VDP protocol + mailbox + dirty tracker
        ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/mailbox.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/dirty_tracker.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/node_registry.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/vdp_session.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/distrib/dist_runtime.cpp

        # FFI - puente plugins nativos
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ffi/native_ffi.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ffi/virtual_lib_registry.cpp

        # Class registry (POO dinamica + reflexion + AOP)
        ${CMAKE_CURRENT_SOURCE_DIR}/src/loader/class_registry.cpp

        # Net (TCP server / TLS) - usado por dist_runtime para VDP
        ${CMAKE_CURRENT_SOURCE_DIR}/src/net/connection.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/net/net.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/net/tcp_server.cpp

        # Util compartido necesario por runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/util/ThreadPool.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/util/sqlite_singleton.cpp

        # Controller TLS (usado por VDP)
        ${CMAKE_CURRENT_SOURCE_DIR}/src/controller/tls_connection.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/controller/tls_context.cpp

        # Phase C/D.0 (snapshot 2026-05-13): C ABI estable + ABI checks +
        # infraestructura JIT inicial (code cache, runtime entries, bridge).
        # vesta_rt incluye estos archivos para que el binario JIT-eado
        # pueda enlazarse contra la libreria sin arrastrar el frontend.
        ${CMAKE_CURRENT_SOURCE_DIR}/src/vesta_rt/public_wrapper.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/vesta_rt/abi_checks.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit/code_cache.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit/runtime_entries.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit/x86_encoder.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit/jit_branch_prof.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit/jit_registry.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jit/stack_scan.cpp

        # Opcion W Fase 3b: serializer IR.  Necesario para que el Loader
        # (en vesta_rt) deserialize la seccion @ir del .velb v3.
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ir/ir_facts.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ir/ir_pattern.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ir/ssa_ir.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ir/ssa_ir_serialize.cpp
)

add_library(vesta_rt STATIC ${VESTA_RT_SOURCES})
target_include_directories(vesta_rt PUBLIC ${VM_INCLUDES})
target_link_libraries(vesta_rt
        PUBLIC sqlite3 miniz
)
if (WIN32)
    target_link_libraries(vesta_rt PUBLIC vesta_openssl ws2_32 synchronization)
else ()
    target_link_libraries(vesta_rt PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif ()
# La MISMA lista que el resto del codigo, no una copia.
#
# Aqui habia una escrita a mano, y ademas solo cubria Release: en Profile este
# runtime se compilaba SIN NINGUNA opcion, o sea sin optimizar, mientras todo lo
# demas iba a `-O3`.  Un perfil sacado asi describe un programa que no es el que
# se ejecuta, que es justo lo contrario de para lo que sirve el modo Profile.
#
# Debug se deja como estaba a proposito: los flags de depuracion del nucleo
# incluyen `-DVM_DEBUG_CHECKS`, y `vesta_rt` es el runtime que se enlaza DENTRO
# de los programas del usuario en AOT -- meterle aserciones ahi es una decision
# de diseno, no una limpieza.
target_compile_options(vesta_rt PRIVATE
        -D__STDC_LIMIT_MACROS
        -D__STDC_CONSTANT_MACROS
        $<$<CONFIG:Release>:${VESTA_OPTS_CODIGO_RELEASE};-fomit-frame-pointer>
        $<$<CONFIG:Profile>:${VESTA_OPTS_CODIGO_RELEASE};-g;-fno-omit-frame-pointer>
)

# Los tests.
#
# Se pueden dejar fuera, y hace falta poder: el paso previo de CPack construye
# el objetivo `all`, asi que con los tests dentro, EMPAQUETAR exige que compilen
# TODOS -- y un test roto impide publicar una version, que es una dependencia
# que no deberia existir.  Por defecto se construyen, como hasta ahora; el
# empaquetado configura con esto en OFF.
#
# Es la misma convencion que ya usa el preprocesador (`VPP_BUILD_TESTS`), al
# que este mismo fichero se lo pone en OFF unas lineas mas arriba.
option(VESTA_BUILD_TESTS "Compilar los tests unitarios de C++" ON)
if (VESTA_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Configuracion global del SDK de plugins nativos
# Debe quedar fuera de los bloques opcionales para que VESTA_SDK_DIR y
# CMAKE_MODULE_PATH esten disponibles en stdlib, examples y cualquier
# subdirectorio futuro que use add_vesta_plugin().
# ---------------------------------------------------------------------------
set(VESTA_SDK_DIR "${CMAKE_SOURCE_DIR}" CACHE PATH
    "Raiz del SDK VestaVM (directorio con include/ffi/vesta_plugin.h)")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# Donde va cada cosa de una instalacion.  Va ANTES de los plugins porque
# `add_vesta_plugin` coloca su .dll/.so dentro del arbol de la stdlib y necesita
# saber donde esta ese arbol; el empaquetado lo vuelve a incluir mas abajo.
include(VestaInstallDirs)

# Libreria estandar nativa (vesta_io, vesta_math, ...)
option(VESTA_BUILD_STDLIB   "Compilar la libreria estandar nativa de Vesta" ON)
if(VESTA_BUILD_STDLIB)
    add_subdirectory(stdlib/native)
endif()

# Ejemplos y plugins de demostracion
option(VESTA_BUILD_EXAMPLES "Compilar los ejemplos y plugins de ejemplo"    ON)
if(VESTA_BUILD_EXAMPLES)
    add_subdirectory(examples_codes_vm/plugin_ejemplo)
endif()

# ---------------------------------------------------------------------------
# Empaquetado (CPack): reglas install() + generadores NSIS/.exe, WiX/.msi, ZIP.
# Genera el instalador con:  cpack --config <build>/CPackConfig.cmake -G NSIS
# ---------------------------------------------------------------------------
include(VestaPackaging)
# Los mandos del entorno: que la tabla este bien formada y que las huellas
# reaccionen a lo que cambia el binario y a nada mas.  Las dos formas de fallar
# son opuestas: de menos, la cache sirve un artefacto de otra configuracion; de
# mas, pedir tiempos recompila el proyecto entero.
add_executable(test_util_env_flags tests/util/test_env_flags.cpp)
target_include_directories(test_util_env_flags PRIVATE ${VM_INCLUDES})
target_link_libraries(test_util_env_flags PRIVATE vmcore sqlite3 capstone keystone)

# ---------------------------------------------------------------------------
# Los tests, fuera del objetivo `all` cuando no se piden.
# ---------------------------------------------------------------------------
# `VESTA_BUILD_TESTS` ya decide si se anade el subdirectorio `tests/`, pero
# aqui mismo hay otros sesenta y cinco ejecutables de prueba declarados sueltos,
# repartidos por todo el fichero.  Envolverlos en un `if()` significaria un
# bloque de mil lineas que ademas contiene codigo que no es de tests, asi que se
# les quita la marca de una vez, al final, cuando ya estan todos declarados.
#
# Importa porque el paso previo de CPack construye `all`: mientras un solo test
# no compile, no se puede generar el instalador.  Que publicar una version
# dependa de que compilen los tests es una dependencia que no deberia existir.
#
# Siguen construyendose por su nombre (`cmake --build . --target test_x`); lo
# unico que cambia es que no entran en la construccion por defecto.
if (NOT VESTA_BUILD_TESTS)
    get_property(_vesta_dir_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    foreach(_t IN LISTS _vesta_dir_targets)
        if (_t MATCHES "^test_")
            set_target_properties(${_t} PROPERTIES EXCLUDE_FROM_ALL TRUE)
        endif()
    endforeach()
endif()
