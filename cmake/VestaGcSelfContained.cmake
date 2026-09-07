# Comprueba que `libvesta_gc.a` solo dependa de libc.
#
# Se ejecuta con `cmake -P` tras construir el archivo.  Recibe:
#   NM       ruta a `nm`
#   ARCHIVO  el .a a mirar
#
# POR QUE EXISTE.  El archivo promete ser enlazable por NUESTRO enlazador sin
# g++ ni libstdc++, y esa promesa no la comprobaba nadie: un archivo estatico
# admite referencias sin resolver, asi que se construia verde con simbolos
# inexistentes y el fallo salia mucho despues, al enlazar un binario AOT con
# `gc<T>`, dicho por el enlazador y con los nombres sin descomponer.
#
# LO QUE SE PERMITE PEDIR es libc y poco mas.  La lista es explicita a proposito:
# una lista de lo permitido se revisa; una de lo prohibido se queda corta sola.
# Si aparece un simbolo legitimo nuevo, se anade AQUI, y anadirlo es la ocasion
# de preguntarse si el archivo sigue siendo freestanding.

execute_process(COMMAND "${NM}" -u "${ARCHIVO}"
                OUTPUT_VARIABLE SALIDA RESULT_VARIABLE CODIGO
                ERROR_VARIABLE ERRORES)
if (NOT CODIGO EQUAL 0)
    message(FATAL_ERROR "vesta_gc: `nm -u` fallo sobre ${ARCHIVO}: ${ERRORES}")
endif ()

# Lo que el archivo DEFINE, para restarlo.
#
# `nm -u` sobre un archivo lista los indefinidos de cada objeto POR SEPARADO,
# sin resolverlos entre miembros: un metodo definido en `gc_heap.cpp` y usado
# desde `gc_lib.cpp` sale como pendiente aunque este ahi al lado.  Sin esta
# resta, el comprobador acusaba de faltar a media docena de metodos del propio
# GC -- un guardian que grita por lo que si esta se desactiva solo, porque el
# siguiente aprende a no mirarlo.
execute_process(COMMAND "${NM}" --defined-only "${ARCHIVO}"
                OUTPUT_VARIABLE DEFINIDOS_CRUDO RESULT_VARIABLE CODIGO_D
                ERROR_VARIABLE ERRORES_D)
if (NOT CODIGO_D EQUAL 0)
    message(FATAL_ERROR
            "vesta_gc: `nm --defined-only` fallo sobre ${ARCHIVO}: ${ERRORES_D}")
endif ()
set(DEFINIDOS "")
string(REPLACE "\n" ";" LINEAS_D "${DEFINIDOS_CRUDO}")
foreach (LINEA IN LISTS LINEAS_D)
    string(STRIP "${LINEA}" LINEA)
    # "0000000000000000 T simbolo"; la clase es una letra suelta.
    if (LINEA MATCHES "^[0-9a-fA-F]+ +[A-Za-z] +(.+)$")
        list(APPEND DEFINIDOS "${CMAKE_MATCH_1}")
    endif ()
endforeach ()

# Lo que un binario AOT ya resuelve por su cuenta (IAT en PE, PLT en ELF), mas
# lo que aporta el propio programa.
set(PERMITIDOS
        # libc
        "^_?malloc$" "^_?free$" "^_?calloc$" "^_?realloc$" "^_?abort$"
        "^_?memcpy$" "^_?memmove$" "^_?memset$" "^_?memcmp$"
        "^_?strlen$" "^_?strcmp$" "^_?strncmp$" "^_?strcpy$" "^_?strncpy$"
        "^_?fprintf$" "^_?printf$" "^_?snprintf$" "^_?fputs$" "^_?fflush$"
        "^_?exit$" "^_?atexit$" "^_?qsort$" "^_?atoi$" "^_?getenv$"
        "^__acrt_iob_func$" "^_?stderr$" "^_?stdout$"
        # API del sistema (Windows), que el AOT resuelve por la IAT
        "^__imp_" "^Virtual" "^GetSystemInfo$" "^GetCurrentProcess"
        "^GetCurrentThread" "^CreateThread$" "^CloseHandle$" "^Sleep$"
        "^WaitOnAddress$" "^WakeByAddress" "^GetLastError$"
        # Capa NT (ntdll).  PERMITIDA, y no como concesion: es la DLL mas basica
        # del sistema -- esta cargada en TODO proceso de Windows antes que
        # kernel32, que de hecho se apoya en ella --, asi que un binario AOT la
        # resuelve por la IAT igual que kernel32.  El asignador baja ahi a
        # proposito: `NtAllocateVirtualMemory` es lo que `VirtualAlloc` llama por
        # debajo, con una capa menos.  El enlazador la lleva en sus DLL
        # candidatas (ver `src/aot/linker.cpp`); si se quitara de alli, esto
        # dejaria de ser cierto y habria que quitarlo de aqui tambien.
        "^Nt[A-Z]" "^Zw[A-Z]" "^Rtl[A-Z]"
        # POSIX
        "^mmap$" "^munmap$" "^mprotect$" "^sysconf$" "^pthread_"
        # La BASE DE LA IMAGEN.  No la define ningun fichero: la publica NUESTRO
        # enlazador, igual que hacen `link.exe` y `ld` (ver `es_base_de_imagen`
        # en `src/aot/linker.cpp`).  Se permite porque se resuelve de verdad; si
        # alguien quitara esa resolucion, esto tendria que salir de aqui.
        "^_?__ImageBase$" "^___ImageBase$" "^__executable_start$"
        # Relleno del enlazador y del propio compilador
        "^__chkstk" "^___chkstk" "^__stack_chk" "^__gxx_personality"
        "^_GLOBAL_OFFSET_TABLE_$" "^__cxa_atexit$" "^__dso_handle$")

set(SOBRAN "")
string(REPLACE "\n" ";" LINEAS "${SALIDA}")
foreach (LINEA IN LISTS LINEAS)
    string(STRIP "${LINEA}" LINEA)
    # `nm -u` imprime "                 U simbolo".
    if (NOT LINEA MATCHES "^U +(.+)$")
        continue()
    endif ()
    set(SIMBOLO "${CMAKE_MATCH_1}")
    # `list(FIND)` y no `IN_LIST`: este fichero se ejecuta con `cmake -P`, y ahi
    # las politicas no vienen puestas del proyecto.  `IN_LIST` depende de
    # CMP0057, asi que con un cmake donde esa politica no esta en NEW -- el que
    # trae el IDE, sin ir mas lejos -- el guardian moria con "Unknown arguments
    # specified" y se llevaba por delante el build entero.  Un comprobador que
    # rompe la construccion en unas maquinas y en otras no es peor que no
    # tenerlo.
    list(FIND DEFINIDOS "${SIMBOLO}" IDX_DEF)
    if (NOT IDX_DEF EQUAL -1)
        continue()  # lo define el propio archivo, en otro objeto
    endif ()
    set(VALE FALSE)
    foreach (PATRON IN LISTS PERMITIDOS)
        if (SIMBOLO MATCHES "${PATRON}")
            set(VALE TRUE)
            break()
        endif ()
    endforeach ()
    if (NOT VALE)
        list(APPEND SOBRAN "${SIMBOLO}")
    endif ()
endforeach ()

if (SOBRAN)
    list(REMOVE_DUPLICATES SOBRAN)
    list(SORT SOBRAN)
    string(REPLACE ";" "\n    " TEXTO "${SOBRAN}")
    message(FATAL_ERROR
            "libvesta_gc.a pide simbolos que un binario AOT no puede resolver:\n"
            "    ${TEXTO}\n\n"
            "El archivo tiene que depender SOLO de libc: es lo que permite\n"
            "enlazar `gc<T>` con nuestro enlazador, sin g++ ni libstdc++.\n"
            "O se anade la definicion al objetivo `vesta_gc` (o al shim\n"
            "`src/vesta_gc/freestanding_shim.cpp`, que es donde se paga lo que\n"
            "libstdc++ daria), o -- si de verdad es legitimo y el AOT lo\n"
            "resuelve solo -- se anade a la lista de PERMITIDOS de\n"
            "cmake/VestaGcSelfContained.cmake, que es la ocasion de\n"
            "preguntarse si el archivo sigue siendo freestanding.")
endif ()
