cmake_minimum_required(VERSION 3.20)
project(VMTests)

# ============================================================================
# Los tests unitarios comparten UN nucleo compilado, no una copia por test.
#
# Antes cada ejecutable de test se declaraba con todas las fuentes de `src/`
# dentro: `add_executable(test_X test_X.cpp ${TODAS_LAS_FUENTES})`.  Con ~150
# tests y ~280 fuentes eso son mas de cuarenta mil compilaciones para construir
# la carpeta, cada una repitiendo exactamente el mismo trabajo que la anterior.
# El efecto practico no era "tarda": era que nadie los construia nunca, y por
# eso se pudrian sin que se notara -- un test dejo de compilar al cambiar la
# firma de `asm_analyze_block` y siguio roto porque el build jamas llegaba a el.
#
# Ahora `src/` se compila una vez en `vesta_test_core` y cada test aporta solo
# su propia unidad.  Mismas opciones, mismas macros, mismo resultado: lo unico
# que cambia es que el trabajo no se repite.
# ============================================================================

# Forzar Debug si no se especifica
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif ()

# ---------------------------------------------------------------------------
# Fuentes del nucleo.
# ---------------------------------------------------------------------------

# Lo unico que compila este directorio es lo que NINGUNA libreria del proyecto
# ofrece ya.
#
# Antes compilaba `src/` ENTERO -- ~275 unidades --, o sea una tercera copia de
# la maquina (`vmcore`) y del frontend (`vx_lib`) junto a la del ejecutable y la
# de la DLL.  Medido con .ninja_log, esa copia sola era el 23,9% del build.
#
# Los tres directorios que quedan aqui son los que no tienen libreria propia:
# el modo analisis, el portador a C y el servidor LSP.  Cuando la tengan, esta
# lista se queda vacia.
file(GLOB_RECURSE ALL_PROJECT_SOURCES
        ${CMAKE_SOURCE_DIR}/src/analyze/*.cpp
        ${CMAKE_SOURCE_DIR}/src/port/*.cpp
        ${CMAKE_SOURCE_DIR}/src/lsp/*.cpp
)

# Del servidor LSP se excluye SOLO su main().
#
# Antes se excluia el directorio entero, y eso dejaba sin compilar el resto del
# modulo -- que es justo lo que prueban los tests de tests/lsp/.  El resultado
# era que esos tests no enlazaban nunca (`lsp::DocumentStore::open` sin definir),
# o sea que estaban muertos sin que nada lo dijera.  Lo que colisiona con el
# main() de cada test es un unico fichero, asi que es lo unico que se quita.
list(FILTER ALL_PROJECT_SOURCES EXCLUDE REGEX "/src/lsp/lsp_main\\.cpp$")

# ---------------------------------------------------------------------------
# Lo que comparten el nucleo y cada test: includes, macros, opciones y enlace.
#
# Va en un target INTERFACE en vez de repetirse en cada sitio porque el nucleo y
# los tests tienen que compilarse con EXACTAMENTE las mismas macros: si un
# `-DVM_DEBUG_CHECKS` cayera solo en un lado, la misma estructura tendria dos
# tamanos distintos a cada lado del enlace y el fallo saldria en ejecucion, no
# al compilar.
# ---------------------------------------------------------------------------
add_library(vesta_test_flags INTERFACE)

target_include_directories(vesta_test_flags INTERFACE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/libs/SourceCode/json
        ${CMAKE_SOURCE_DIR}/libs/SourceCode/cxxopts
        ${CMAKE_SOURCE_DIR}/libs/SourceCode/capstone/include
        ${CMAKE_SOURCE_DIR}/libs/SourceCode/keystone/include
        ${CMAKE_SOURCE_DIR}/libs/SourceCode/DistanciaLevenshtein
)

target_link_libraries(vesta_test_flags
        INTERFACE sqlite3
        INTERFACE keystone
        INTERFACE aot_emit
)

# `synchronization` es de Windows -- da `WaitOnAddress`/`WakeByAddress`, que en
# POSIX cubre `futex` --, y estaba sin condicion: en Linux el enlazador la
# buscaba y no la encontraba, asi que NINGUN test enlazaba.  Y eso no se queda
# en los tests: rompe el objetivo `all`, del que cuelga el paso previo de CPack,
# con lo que tampoco se podia generar el instalador.  El bloque de OpenSSL de
# aqui abajo ya distinguia la plataforma; esta linea se le habia escapado.
if (WIN32)
    target_link_libraries(vesta_test_flags INTERFACE synchronization)
endif ()

# `capstone` NO va aqui: es una libreria de OBJETOS, y sus objetos solo entran
# en el ejecutable si se enlaza DIRECTAMENTE contra el.  Pasando por un target
# INTERFACE se heredan sus includes pero no su codigo, y el resultado son
# `cs_open`/`cs_disasm` sin definir al final del enlace.  Se anade en
# add_single_test, sobre el ejecutable.

# OpenSSL: enlace centralizado en `vesta_openssl`.
if (WIN32)
    target_link_libraries(vesta_test_flags INTERFACE vesta_openssl ws2_32)
else ()
    target_link_libraries(vesta_test_flags INTERFACE vesta_openssl)
endif ()

# pthread solo Linux/macOS
if (NOT WIN32)
    target_link_libraries(vesta_test_flags INTERFACE pthread)
endif ()

# Opciones globales para todos los builds
target_compile_options(vesta_test_flags INTERFACE
        -D__STDC_LIMIT_MACROS
        -D__STDC_CONSTANT_MACROS
        -pedantic-errors
)

# Opciones por configuracion
target_compile_options(vesta_test_flags INTERFACE
        $<$<CONFIG:Debug>:
        -g -O0 -DVM_DEBUG_CHECKS # anadir checks para depuracion.
        -Wall -Wextra -fno-omit-frame-pointer -DMODE_DEBUG_ENABLE
        -DDEBUG_EMIT        # permitir mostrar el proceso de emision de codigo
        >
        # Release y Profile usan LA MISMA lista que el producto, no una copia.
        #
        # Aqui habia una copia escrita a mano, y habia divergido: llevaba
        # `-ffast-math` y `-mtune=native` cuando el producto ya no.  Un test que
        # compila las MISMAS fuentes con otra semantica no prueba el programa
        # que se publica, prueba otro -- y la forma de enterarse seria un test
        # que pasa aqui y falla en produccion, o al reves.
        #
        # Profile no estaba contemplado: los tests se compilaban SIN ninguna
        # opcion en ese modo.
        $<$<CONFIG:Release>:${VESTA_OPTS_CODIGO_RELEASE};-fomit-frame-pointer>
        $<$<CONFIG:Profile>:${VESTA_OPTS_CODIGO_RELEASE};-g;-fno-omit-frame-pointer>
        $<$<CONFIG:RelWithDebInfo>:-fpermissive -g -O1 -fno-omit-frame-pointer>
)

# ---------------------------------------------------------------------------
# Opciones de ENLACE (solo tienen sentido en los ejecutables, no en el archivo).
# ---------------------------------------------------------------------------
add_library(vesta_test_link INTERFACE)

if (WIN32)
    target_link_options(vesta_test_link INTERFACE -static)
endif ()

# release
target_link_options(vesta_test_link INTERFACE
        $<$<CONFIG:Release>:
        # --- Eliminacion de codigo muerto ---
        -Wl,--gc-sections          # Elimina funciones/datos no usados
        # --- Reduccion de tamano ---
        -Wl,--strip-all            # Elimina todos los simbolos
        -Wl,--as-needed            # Solo enlaza libs realmente usadas
        -Wl,--build-id=none        # No genera build-id (reduce tamano)
        >
)

# Enlace estatico solo en Windows + Release
target_link_options(vesta_test_link INTERFACE
        $<$<AND:$<CONFIG:Release>,$<BOOL:${WIN32}>>:
        -static                    # Binario autonomo
        -static-libgcc             # Libgcc estatica
        -static-libstdc++          # Libstdc++ estatica
        >
)

# ---------------------------------------------------------------------------
# El nucleo, compilado UNA vez.
# ---------------------------------------------------------------------------
if (NOT ASM_INTEL)
    add_library(vesta_test_core STATIC ${ALL_PROJECT_SOURCES})
    # El nucleo y el frontend se ENLAZAN, no se recompilan.  `vesta_vm_flags`
    # llega por `vmcore`, asi que estas unidades se compilan exactamente con las
    # mismas macros que el codigo que se entrega -- que es la unica forma de que
    # un test pruebe el mismo programa.
    target_link_libraries(vesta_test_core
            PUBLIC vesta_test_flags
            PUBLIC vmcore
            PUBLIC vx_lib
            PUBLIC vesta_toolchain)
endif ()

# ---------------------------------------------------------------------------
# Un ejecutable por fichero de test.
# ---------------------------------------------------------------------------

##
# @brief Declara el ejecutable de un test.
# @param PREFIX      Prefijo del nombre, derivado del directorio.
# @param TEST_FILE   Fichero .cpp del test.
# @param ALL_SOURCES Fuentes del nucleo; solo se usan en el modo ASM_INTEL, que
#                    vuelca ensamblador y no enlaza nada.
function(add_single_test PREFIX TEST_FILE ALL_SOURCES)
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
    set(FINAL_NAME "${PREFIX}_${TEST_NAME}")

    # Si estamos en modo AsmIntel, forzar flags en el target
    if (ASM_INTEL)
        add_executable(${FINAL_NAME} ${TEST_FILE} ${ALL_SOURCES})
        target_compile_options(${FINAL_NAME} PRIVATE -S -masm=intel -fverbose-asm -O0)

        # No enlazar
        set_target_properties(${FINAL_NAME} PROPERTIES
                EXCLUDE_FROM_ALL TRUE
                LINKER_LANGUAGE CXX
        )
        return()
    endif ()

    add_executable(${FINAL_NAME} ${TEST_FILE})
    # Archivo COMPLETO del nucleo: hay unidades que solo se registran solas al
    # arrancar y a las que nadie llama por su nombre; de un archivo normal el
    # enlazador no las saca.  (`capstone` ya viene dentro de `vmcore`.)
    target_link_libraries(${FINAL_NAME}
            PRIVATE vesta_test_core
            PRIVATE $<LINK_LIBRARY:WHOLE_ARCHIVE,vmcore>
            PRIVATE vesta_test_link)
endfunction()

# Buscar todos los archivos .cpp dentro de tests/ y subcarpetas
file(GLOB_RECURSE TEST_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp)

foreach (TEST_FILE ${TEST_FILES})
    # Crear un prefijo seguro basado en la ruta relativa
    get_filename_component(TEST_DIR ${TEST_FILE} DIRECTORY)
    string(REPLACE "/" "_" REL_DIR_SAFE ${TEST_DIR})
    add_single_test("test_${REL_DIR_SAFE}" ${TEST_FILE} "${ALL_PROJECT_SOURCES}")
endforeach ()
