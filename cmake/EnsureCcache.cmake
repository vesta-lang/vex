# =============================================================================
#  EnsureCcache.cmake -- cache de compilador, sin pedirle nada al usuario.
# -----------------------------------------------------------------------------
#  QUE RESUELVE.  El 92% del tiempo de compilar este proyecto se va en optimizar
#  y generar codigo, no en leer cabeceras (medido con `-ftime-report` sobre
#  `lowering.cpp`: parsing 5%, plantillas 3%, optimizar 92%).  Contra eso no
#  sirven las cabeceras precompiladas -- se probaron y salieron peor, ver el
#  CMakeLists principal --: lo unico que ahorra ese 92% es NO volver a
#  generarlo.
#
#  Eso es exactamente lo que hace una cache de compilador: guarda el objeto
#  indexado por el fuente preprocesado y las opciones, asi que recompilar algo
#  que ya se compilo antes -- cambiar de rama y volver, reconfigurar, deshacer
#  un cambio, reconstruir en otro directorio de build -- no vuelve a optimizar
#  nada: copia el resultado.
#
#  PORTABLE Y AUTO-DESCARGADA.  `ccache` publica binarios ya construidos para
#  Windows, Linux y macOS que funcionan al extraerlos, sin instalador.  En Linux
#  se cogen los enlazados con musl ESTATICAMENTE: no dependen de la version de
#  glibc de la maquina, que es lo que convierte un binario ajeno en un problema.
#
#  Si no hay red, o la plataforma no esta en la lista, no pasa nada: el build
#  sigue sin cache.  Esto acelera, no habilita.
#
#  Salida:
#    VESTA_CCACHE   ruta al ejecutable, o vacio.
# =============================================================================

##
# @brief Deja en @p _out el ejecutable de una cache de compilador, o vacio.
# @param _dir  Donde extraer la que se descargue (compartida entre build dirs).
# @param _out  Variable de salida.
function(vesta_ensure_ccache _dir _out)
    set(${_out} "" PARENT_SCOPE)

    # -- 1. Una del sistema, si la hay.  Gratis. ---------------------------
    #  sccache tambien vale: hace lo mismo y CMake lo usa igual.
    find_program(_vesta_cc_sys NAMES ccache sccache)
    if (_vesta_cc_sys)
        set(${_out} "${_vesta_cc_sys}" PARENT_SCOPE)
        return()
    endif()

    # -- 2. Una ya descargada por otro directorio de build. ----------------
    #  Solo la de ESTA plataforma.  El directorio `.deps/` se comparte entre
    #  builds, y en este arbol se comparte ademas entre Windows y Linux (WSL ve
    #  el mismo disco): sin filtrar, un build de Linux cogia el `ccache.exe` que
    #  habia dejado el de Windows.  WSL lo EJECUTA -- hay interoperabilidad --,
    #  asi que no fallaba al elegirlo sino al usarlo, y cada compilacion moria
    #  con "execute_noreturn of /usr/bin/cc failed: Invalid argument".  El build
    #  entero se caia por una cache que solo pretendia ir mas rapido.
    if (CMAKE_HOST_WIN32)
        file(GLOB _prev "${_dir}/*/ccache.exe" "${_dir}/ccache.exe")
    else()
        file(GLOB _prev "${_dir}/*/ccache" "${_dir}/ccache")
    endif()
    if (_prev)
        list(GET _prev 0 _p)
        set(${_out} "${_p}" PARENT_SCOPE)
        return()
    endif()

    # -- 3. Descargarla. ---------------------------------------------------
    set(_ver "4.13.6")

    #  Que binario le toca a esta maquina.  Campos separados por `|` porque una
    #  lista de CMake ya usa `;` y un elemento que lo contenga se partiria.
    #  (sufijo del artefacto | SHA-256)
    set(_pick "")
    set(_host_cpu "${CMAKE_HOST_SYSTEM_PROCESSOR}")
    string(TOLOWER "${_host_cpu}" _host_cpu)
    if (CMAKE_HOST_WIN32)
        if (_host_cpu MATCHES "arm64|aarch64")
            set(_pick "windows-aarch64.zip|bec01846b06d6d87bf35eda50544d7c8bf9b9a4859f218417a7081aa45d7fd47")
        else()
            set(_pick "windows-x86_64.zip|3d7cebb05850ad704e197b3f1d3f0f924ab6c9fdfc561578e146184fe9d89380")
        endif()
    elseif (CMAKE_HOST_APPLE)
        # Un solo artefacto universal (Intel + Apple Silicon).
        set(_pick "darwin.tar.gz|0274210ec9c9936ed5711d59b0de3167a51216a588ddde35f6bc828f366fe6d9")
    elseif (CMAKE_HOST_UNIX)
        if (_host_cpu MATCHES "arm64|aarch64")
            set(_pick "linux-aarch64-musl-static.tar.xz|2098d561e4a8e36bd06a29aedce53ea90c7e365f9573a93d91c230efbf96a958")
        elseif (_host_cpu MATCHES "x86_64|amd64")
            set(_pick "linux-x86_64-musl-static.tar.xz|156ec57c5198cc849d92834023d09910b83dc5504c6cf405d09e6ae7b208a3e5")
        endif()
    endif()

    if (NOT _pick)
        message(STATUS "[ccache] sin binario para ${CMAKE_HOST_SYSTEM_NAME}/${_host_cpu}; se compila sin cache")
        return()
    endif()

    string(REPLACE "|" ";" _f "${_pick}")
    list(GET _f 0 _suffix)
    list(GET _f 1 _sha)
    set(_name "ccache-${_ver}-${_suffix}")
    set(_url "https://github.com/ccache/ccache/releases/download/v${_ver}/${_name}")
    set(_arch "${_dir}/${_name}")

    file(MAKE_DIRECTORY "${_dir}")
    message(STATUS "[ccache] descargando ${_name} (SHA-256 fijado)...")
    file(DOWNLOAD "${_url}" "${_arch}" EXPECTED_HASH SHA256=${_sha} STATUS _st)
    list(GET _st 0 _code)
    if (NOT _code EQUAL 0)
        list(GET _st 1 _msg)
        file(REMOVE "${_arch}")
        message(STATUS "[ccache] descarga fallo (${_code}): ${_msg}; se compila sin cache")
        return()
    endif()

    file(ARCHIVE_EXTRACT INPUT "${_arch}" DESTINATION "${_dir}")
    file(GLOB _found "${_dir}/*/ccache" "${_dir}/*/ccache.exe" "${_dir}/ccache"
                     "${_dir}/ccache.exe")
    if (NOT _found)
        message(STATUS "[ccache] el paquete no traia el ejecutable; se compila sin cache")
        return()
    endif()
    list(GET _found 0 _p)
    if (NOT CMAKE_HOST_WIN32)
        # Los tarballs conservan el permiso, pero un zip no; asegurarlo no
        # cuesta nada y evita un "permission denied" al primer objeto.
        execute_process(COMMAND chmod +x "${_p}" ERROR_QUIET)
    endif()
    set(${_out} "${_p}" PARENT_SCOPE)
endfunction()

##
# @brief Enchufa la cache como lanzador del compilador, si hay alguna.
#
# Se hace con COMPILER_LAUNCHER y no sustituyendo el compilador: asi CMake
# sigue viendo el compilador REAL al detectar sus capacidades, y quitar la cache
# no cambia ni una opcion de compilacion.
function(vesta_setup_ccache)
    if (NOT VESTA_USE_CCACHE)
        # Y se QUITA la que hubiera puesto una configuracion anterior.  El
        # lanzador se guarda en la cache de CMake con FORCE, asi que volver a
        # configurar con el interruptor apagado lo dejaba puesto igual: el
        # apagado no apagaba nada, que es peor que no tener interruptor.
        unset(CMAKE_C_COMPILER_LAUNCHER   CACHE)
        unset(CMAKE_CXX_COMPILER_LAUNCHER CACHE)
        return()
    endif()
    vesta_ensure_ccache("${CMAKE_SOURCE_DIR}/.deps/ccache" _cc)
    if (NOT _cc)
        return()
    endif()
    message(STATUS "[ccache] cache de compilador activa: ${_cc}")

    # Modo DEPEND, y por que se fuerza aqui.
    #
    # En el modo por defecto la cache preprocesa, compara y, al acertar,
    # restaura el objeto Y su fichero de dependencias.  Si esa restauracion no
    # ocurre -- entrada vieja, otra version de la cache --, el generador lee un
    # fichero de dependencias vacio y anota que ese objeto NO DEPENDE DE NINGUNA
    # CABECERA.  A partir de ahi ningun cambio de cabecera lo recompila, y se
    # enlaza contra codigo viejo sin que nada lo diga.  Aparecio con cinco
    # objetos en ese estado.
    #
    # En modo depend la cache usa el fichero de dependencias como parte de la
    # clave, asi que dejarlo de lado no es una opcion para ella.  No esta
    # demostrado que fuera LA causa; se pone porque cierra ese camino y ademas
    # es mas rapido (no preprocesa dos veces).  Quien lo vigila de verdad es
    # `tools/check_build_deps.py`.
    #
    # Se pasa por el entorno de CADA compilacion, y no con `--set-config`, para
    # no escribir en la configuracion global de quien compila: un proyecto no
    # debe cambiarle los ajustes a los demas que tenga esa persona.
    #
    # Aviso: cambiar de modo invalida lo cacheado, asi que la primera
    # compilacion despues de esto es completa.
    set(_launcher "${CMAKE_COMMAND}" -E env CCACHE_DEPEND=1 "${_cc}")
    set(CMAKE_C_COMPILER_LAUNCHER   "${_launcher}" CACHE STRING "" FORCE)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${_launcher}" CACHE STRING "" FORCE)
endfunction()
