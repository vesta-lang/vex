# =============================================================================
#  MakeInstallerLinux.cmake -- los paquetes de Linux, generados DESDE Windows.
# -----------------------------------------------------------------------------
#  Se ejecuta en modo script:
#
#    cmake -DSRC_DIR=<fuente> -DOUT_DIR=<build de Windows> \
#          [-DDISTRO=<nombre>] [-DFORMATOS=DEB;RPM;TGZ] [-DEXTRA_ARGS=...] \
#          -P cmake/MakeInstallerLinux.cmake
#
#  DE DONDE SALE EL COMPILADOR: de WSL, nunca de Windows.
#
#  Generar el paquete de Linux NO debe depender de que este Windows tenga uno u
#  otro compilador de C -- aqui se usa TDM-GCC, en otra maquina sera MSVC o
#  ninguno --.  El compilador, el enlazador y las herramientas de empaquetado
#  son los que tenga la distribucion de WSL; de Windows solo hace falta `cmake`
#  para lanzar esto.  Por eso el script se ejecuta con `-P` y no como objetivo
#  de un proyecto ya configurado: configurar un proyecto de C++ exigiria un
#  compilador de Windows, que es justo lo que se quiere evitar.  (Hay tambien
#  objetivos `installer-linux*` para cuando YA tienes un build de Windows.)
#
#  La otra via -- clang de Windows con `--target` y un sysroot de Linux --
#  quedaria atada al compilador que haya instalado en Windows, y ademas se
#  probo: el rootfs de WSL no vale de sysroot visto desde Windows (da errores de
#  E/S en ficheros sueltos) y materializarlo son 350 MB por distribucion.
#
#  Construir DENTRO de la distribucion tiene ademas una ventaja que no es
#  accesoria: `dpkg-shlibdeps` LEE los binarios ya enlazados y deduce las
#  dependencias reales del paquete.  Compilando contra un sysroot habria que
#  escribir a mano contra que version de glibc se depende, y esa lista envejece
#  en silencio.
#
#  El arbol de construccion se deja DENTRO de WSL y no en el disco de Windows.
#  Los dos se ven, pero el puente entre sistemas de ficheros es lento y aqui se
#  escriben decenas de miles de objetos; el fuente si se lee por el puente,
#  porque es donde vive.  Solo los paquetes terminados cruzan de vuelta.
#
#  En Linux este fichero no se usa: alli estan los objetivos `installer-deb`,
#  `installer-rpm` e `installer-tgz`, que hacen lo mismo sin intermediario.
# =============================================================================

if (NOT DEFINED SRC_DIR OR NOT DEFINED OUT_DIR)
    message(FATAL_ERROR "Faltan -DSRC_DIR y -DOUT_DIR")
endif()
if (NOT DEFINED FORMATOS OR FORMATOS STREQUAL "")
    set(FORMATOS "DEB")
endif()

# --- 1. Que haya WSL, y con una distribucion dentro -------------------------
find_program(WSL_EXE wsl)
if (NOT WSL_EXE)
    message(FATAL_ERROR
        "No se encontro `wsl`.  Los paquetes de Linux se construyen dentro de "
        "una distribucion de WSL -- con SU compilador, para no depender del que "
        "tenga Windows --; instala una con `wsl --install` y vuelve a "
        "intentarlo.")
endif()

# Que la distribucion arranque.  Sin esta comprobacion, un WSL instalado pero
# sin distribucion falla mas tarde y con un mensaje del shell, no de aqui.
set(_wsl_args "")
if (DEFINED DISTRO AND NOT DISTRO STREQUAL "")
    set(_wsl_args -d "${DISTRO}")
endif()
execute_process(COMMAND "${WSL_EXE}" ${_wsl_args} -- bash -lc "echo ok"
                RESULT_VARIABLE _rc OUTPUT_QUIET ERROR_VARIABLE _err)
if (NOT _rc EQUAL 0)
    message(FATAL_ERROR "WSL no responde: ${_err}")
endif()

# --- 2. El fuente, visto desde Linux ----------------------------------------
# Lo traduce `wslpath`, que es quien sabe como esta montado cada disco; hacerlo
# a mano (`F:/x` -> `/mnt/f/x`) da por hecho un punto de montaje que se puede
# haber configurado de otra forma.
#
# Se le pasa la ruta con barras NORMALES, no la nativa de Windows: al cruzar de
# `execute_process` a `wsl.exe` las barras invertidas se consumen como escapes y
# `F:\C\VM` llegaba convertido en `F:CVM`.  `wslpath` acepta las dos formas.
execute_process(COMMAND "${WSL_EXE}" ${_wsl_args} -- wslpath -a "${SRC_DIR}"
                OUTPUT_VARIABLE _src_wsl OUTPUT_STRIP_TRAILING_WHITESPACE
                RESULT_VARIABLE _rc ERROR_VARIABLE _err)
if (NOT _rc EQUAL 0 OR _src_wsl STREQUAL "")
    message(FATAL_ERROR "No se pudo traducir '${SRC_DIR}' a una ruta de WSL: ${_err}")
endif()
message(STATUS "[linux] fuente: ${_src_wsl}")

# --- 3. Las herramientas que hacen falta ------------------------------------
# Se comprueban ANTES de compilar: descubrir que falta `dpkg-deb` despues de
# veinte minutos de compilacion es la peor forma de enterarse.
set(_need "cmake" "g++" "make")
foreach(_f IN LISTS FORMATOS)
    if (_f STREQUAL "DEB")
        list(APPEND _need "dpkg-deb")
    elseif (_f STREQUAL "RPM")
        list(APPEND _need "rpmbuild")
    endif()
endforeach()
string(REPLACE ";" " " _need_str "${_need}")
execute_process(
    COMMAND "${WSL_EXE}" ${_wsl_args} -- bash -lc
            "falta=; for h in ${_need_str}; do command -v $h >/dev/null 2>&1 || falta=\"$falta $h\"; done; echo \"$falta\""
    OUTPUT_VARIABLE _falta OUTPUT_STRIP_TRAILING_WHITESPACE)
string(STRIP "${_falta}" _falta)
if (NOT _falta STREQUAL "")
    message(FATAL_ERROR
        "En la distribucion de WSL faltan estas herramientas:${_falta}\n"
        "  Instalalas dentro de WSL, por ejemplo:\n"
        "    sudo apt install build-essential cmake dpkg-dev rpm")
endif()

# --- 4. Configurar y construir dentro de WSL --------------------------------
# `VESTA_BUILD_TESTS=OFF` no es una preferencia: el paso previo de CPack
# construye el objetivo `all`, asi que con los tests dentro un test roto
# impediria generar el paquete.
set(_build_wsl "$HOME/.cache/vesta/linux-build")
# `-mtune=generic`: el paquete no debe salir afinado para la maquina que lo
# construyo, ni dar un binario distinto segun quien lo construya.
set(_cfg "cmake -S '${_src_wsl}' -B \"${_build_wsl}\" -DCMAKE_BUILD_TYPE=Release -DVESTA_BUILD_TESTS=OFF -DVESTA_TUNE=generic ${EXTRA_ARGS}")
message(STATUS "[linux] configurando...")
execute_process(COMMAND "${WSL_EXE}" ${_wsl_args} -- bash -lc "${_cfg}"
                RESULT_VARIABLE _rc)
if (NOT _rc EQUAL 0)
    message(FATAL_ERROR "Fallo al configurar dentro de WSL.")
endif()

foreach(_f IN LISTS FORMATOS)
    string(TOLOWER "${_f}" _f_low)
    message(STATUS "[linux] generando paquetes ${_f}...")
    execute_process(
        COMMAND "${WSL_EXE}" ${_wsl_args} -- bash -lc
                "cmake --build \"${_build_wsl}\" --target installer-${_f_low} -j \"$(nproc)\""
        RESULT_VARIABLE _rc)
    if (NOT _rc EQUAL 0)
        message(FATAL_ERROR "Fallo al generar los paquetes ${_f} dentro de WSL.")
    endif()
endforeach()

# --- 5. Traer los paquetes al lado de Windows -------------------------------
# El directorio de destino se CREA antes de copiar.  Si no existe, `cp` no
# escribe nada y lo que se ve al final es "no se genero ningun paquete" --
# habiendose generado los dos --, que manda a mirar la compilacion cuando lo que
# fallo fue traerlos.
file(MAKE_DIRECTORY "${OUT_DIR}")
execute_process(COMMAND "${WSL_EXE}" ${_wsl_args} -- wslpath -a "${OUT_DIR}"
                OUTPUT_VARIABLE _out_wsl OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
    COMMAND "${WSL_EXE}" ${_wsl_args} -- bash -lc
            "cp -f \"${_build_wsl}\"/*.deb \"${_build_wsl}\"/*.rpm \"${_build_wsl}\"/*.tar.gz '${_out_wsl}'/ 2>/dev/null; ls -1 '${_out_wsl}'/*.deb '${_out_wsl}'/*.rpm '${_out_wsl}'/*.tar.gz 2>/dev/null"
    OUTPUT_VARIABLE _hechos OUTPUT_STRIP_TRAILING_WHITESPACE)
if (_hechos STREQUAL "")
    # Se distinguen los DOS casos, porque llevan a sitios distintos: o no se
    # construyo nada, o se construyo y no se pudo traer.  Decir siempre lo
    # primero manda a depurar una compilacion que salio bien.
    execute_process(
        COMMAND "${WSL_EXE}" ${_wsl_args} -- bash -lc
                "ls -1 \"${_build_wsl}\"/*.deb \"${_build_wsl}\"/*.rpm \"${_build_wsl}\"/*.tar.gz 2>/dev/null"
        OUTPUT_VARIABLE _dentro OUTPUT_STRIP_TRAILING_WHITESPACE)
    if (_dentro STREQUAL "")
        message(FATAL_ERROR "No se genero ningun paquete dentro de WSL.")
    endif()
    message(FATAL_ERROR
            "Los paquetes SI se generaron, pero no se pudieron copiar a\n"
            "  ${OUT_DIR}\n"
            "Estan dentro de WSL, en ${_build_wsl}:\n${_dentro}")
endif()
message(STATUS "[linux] paquetes en ${OUT_DIR}:")
string(REPLACE "\n" ";" _lista "${_hechos}")
foreach(_p IN LISTS _lista)
    get_filename_component(_n "${_p}" NAME)
    message(STATUS "         ${_n}")
endforeach()
