#
# VestaVM -- Maquina Virtual Distribuida
#
# Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
# Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
#

# Clang con el ABI de MinGW, apoyandose en el sysroot de TDM-GCC.
#
# POR QUE ESTA ABI Y NO LA DE MSVC.  Clang en Windows sabe hablar las dos, y las
# dos compilan este arbol, pero no cuestan lo mismo: con la de MinGW se reusan
# TAL CUAL las dependencias que ya estan construidas -- OpenSSL estatico en
# `.deps/`, keystone, capstone, sqlite --, mientras que la de MSVC obliga a
# rehacerlas todas porque son otro ABI.  Esta es la que sirve para pasar el
# arbol por un segundo compilador sin montar un segundo mundo.
#
# PARA QUE.  No para elegir compilador: para tener DOS.  Cada uno dice cosas que
# el otro se calla, y un arbol que solo pasa por uno acumula en silencio lo que
# ese no mira.
#
# USO:
#   cmake -S . -B cmake-build-clang -G "MinGW Makefiles" \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/clang-mingw.cmake \
#         -DCMAKE_BUILD_TYPE=Release
#
# Las rutas se pueden cambiar sin tocar el fichero:
#   -DVESTA_CLANG_DIR=...     donde estan clang.exe y clang++.exe
#   -DVESTA_MINGW_SYSROOT=... la raiz de TDM-GCC (la que tiene bin/ y lib/)

# NO se pone `CMAKE_SYSTEM_NAME`.  Esto NO es compilacion cruzada: el anfitrion
# es Windows y el objetivo tambien; lo unico que cambia es el compilador.
# Ponerlo activa `CMAKE_CROSSCOMPILING` y, con el, CMake deja de deducir cosas
# que aqui SI se pueden deducir -- entre ellas `CMAKE_SYSTEM_PROCESSOR`, que se
# quedaba VACIO y hacia reventar el `CPackConfig.txt` de capstone con un
# `if(STREQUAL "x86_64")` sin primer argumento.

set(VESTA_CLANG_DIR "C:/Program Files/LLVM/bin"
        CACHE PATH "Directorio con clang.exe / clang++.exe")
set(VESTA_MINGW_SYSROOT "C:/TDM-GCC-64"
        CACHE PATH "Raiz de la instalacion de TDM-GCC usada como sysroot")

set(CMAKE_C_COMPILER   "${VESTA_CLANG_DIR}/clang.exe")
set(CMAKE_CXX_COMPILER "${VESTA_CLANG_DIR}/clang++.exe")

# El triple y el sysroot van en los flags y no en `CMAKE_C_COMPILER_TARGET`
# porque tambien tienen que llegar al paso de ENLACE: sin ellos clang enlazaria
# contra su objetivo por defecto, que en esta maquina es el de MSVC.
set(_vesta_clang_mingw "--target=x86_64-w64-windows-gnu --sysroot=${VESTA_MINGW_SYSROOT}")

# TLS EMULADA, para hablar la misma ABI que el `libstdc++` de TDM.
#
# GCC en MinGW no usa la TLS nativa de Windows: emula las variables `__thread`
# con la capa `emutls` de libgcc.  Clang, por defecto, SI emite TLS nativa.  Las
# dos formas no se entienden entre si, y eso sale al enlazar contra un
# `libstdc++` que se construyo con la otra: `std::call_once` declara dos
# variables `__thread` (`std::__once_call` y `std::__once_callable`) y quedaban
# sin resolver.
#
# El coste habitual de emutls -- una llamada por acceso, medida en este mismo
# proyecto como 12x -- aqui apenas se paga, y no por suerte: este arbol EVITA
# `thread_local` a proposito justo por eso, y usa sus propias ranuras por hilo
# (`util/thread_owned.h`, `util/os/thread_slot.h`).  Lo unico que queda bajo
# emutls es lo que trae la biblioteca estandar por dentro.
set(_vesta_clang_mingw "${_vesta_clang_mingw} -femulated-tls")

# El enlazador es el `ld` de TDM (GNU ld), no `ld.lld`.
#
# CMake 4.x, para la caracteristica WHOLE_ARCHIVE -- la que envuelve
# `libvmcore.a` --, emite `--push-state` / `--pop-state`, que son de GNU ld y
# que `ld.lld` en modo MinGW NO reconoce: el enlace muere con "unknown
# argument".  Y no es un capricho de CMake: son la forma correcta de acotar el
# `--whole-archive` a UN archivo en vez de dejarlo abierto al resto de la linea.
#
# Usar el `ld` de TDM ademas es coherente con todo lo demas: las bibliotecas
# contra las que se enlaza son las suyas.  Comprobado que las excepciones de C++
# siguen funcionando por esta via.
#
# Va SOLO en los flags de enlace, no en los de compilacion: en una compilacion
# es un argumento sin usar, y meterlo ahi cambiaria la linea de ordenes de las
# 621 unidades y las mandaria a recompilar enteras para nada.
set(_vesta_mingw_ld "${VESTA_MINGW_SYSROOT}/bin/ld.exe")
set(_vesta_link_only "")
if (EXISTS "${_vesta_mingw_ld}")
    # `-pthread` SOLO al enlazar.  El `libstdc++.a` de TDM tiene dentro
    # `std::condition_variable` y `std::chrono`, y esos si llaman a winpthreads
    # (`pthread_cond_wait`, `__pthread_clock_gettime`...).  `g++` anyade
    # `-lwinpthread` por su cuenta; el driver de clang solo lo hace si se le
    # pide con `-pthread`, y sin el salian 49 referencias sin definir.
    #
    # Que el propio proyecto EVITE winpthreads en su codigo no quita que la
    # biblioteca estandar con la que se enlaza lo use: son cosas distintas.
    set(_vesta_link_only " -fuse-ld=${_vesta_mingw_ld} -pthread")
else ()
    message(WARNING
            "[clang-mingw] no se encuentra ${_vesta_mingw_ld}; se usara `ld.lld`, "
            "que NO entiende --push-state/--pop-state y hara fallar el enlace de "
            "los targets con WHOLE_ARCHIVE.")
endif ()

set(CMAKE_C_FLAGS_INIT   "${_vesta_clang_mingw}")
set(CMAKE_CXX_FLAGS_INIT "${_vesta_clang_mingw}")
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_vesta_clang_mingw}${_vesta_link_only}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_vesta_clang_mingw}${_vesta_link_only}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_vesta_clang_mingw}${_vesta_link_only}")

# El archivador y el lector de simbolos tienen que ser los de LLVM: los de TDM
# entienden el formato, pero `llvm-ar` es el que va con este clang y es el unico
# que sabe leer los objetos si algun dia se activa LTO.
find_program(CMAKE_AR      NAMES llvm-ar      HINTS "${VESTA_CLANG_DIR}")
find_program(CMAKE_RANLIB  NAMES llvm-ranlib  HINTS "${VESTA_CLANG_DIR}")

# ---------------------------------------------------------------------------
# `libgcc_eh.a` VACIA, y no es un apano: es que TDM no la tiene.
#
# El driver de clang para MinGW pone `-lgcc -lgcc_eh` al enlazar C, dando por
# hecho el reparto habitual de GCC -- las funciones auxiliares en `libgcc.a` y
# el desenrollador aparte, en `libgcc_eh.a` --.  TDM no lo parte asi: solo trae
# `libgcc.a` y `libgcc_s.a`, y el desenrollador esta DENTRO de la primera
# (comprobado: `_Unwind_RaiseException` y companyia salen ahi con `llvm-nm`).
#
# Como `-lgcc` va ANTES en la linea, los simbolos ya estan resueltos cuando se
# llega a `-lgcc_eh`; lo unico que falta es que exista un fichero con ese
# nombre.  Se genera vacio.  Comprobado que no se pierde nada: un programa que
# lanza y captura una excepcion de C++ enlazado asi la captura.
#
# Solo lo ve C.  El driver de C++ enlaza `libstdc++` y no pide `-lgcc_eh`.
# ---------------------------------------------------------------------------
set(_vesta_shim_dir "${CMAKE_BINARY_DIR}/toolchain-shim")
if (NOT EXISTS "${_vesta_shim_dir}/libgcc_eh.a")
    file(MAKE_DIRECTORY "${_vesta_shim_dir}")
    execute_process(COMMAND "${CMAKE_AR}" rcs "${_vesta_shim_dir}/libgcc_eh.a"
                    RESULT_VARIABLE _vesta_shim_rc)
    if (NOT _vesta_shim_rc EQUAL 0)
        message(FATAL_ERROR
                "[clang-mingw] no se pudo crear el `libgcc_eh.a` vacio en "
                "${_vesta_shim_dir}; sin el, el enlace de C falla con "
                "\"unable to find library -lgcc_eh\".")
    endif ()
endif ()

foreach (_v EXE SHARED MODULE)
    set(CMAKE_${_v}_LINKER_FLAGS_INIT
            "${CMAKE_${_v}_LINKER_FLAGS_INIT} -L${_vesta_shim_dir}")
endforeach ()

# Las cabeceras del sysroot son de terceros: que no llenen la salida de avisos
# que no se van a arreglar aqui.
set(CMAKE_INCLUDE_SYSTEM_FLAG_C   "-isystem ")
set(CMAKE_INCLUDE_SYSTEM_FLAG_CXX "-isystem ")
