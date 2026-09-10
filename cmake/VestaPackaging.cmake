# VestaPackaging.cmake
#
# Reglas de instalacion (CPack) para VestaVM.  UNICA fuente de verdad de "que
# archivos forman una instalacion": el instalador generado (NSIS .exe / WiX .msi
# / ZIP portable) empaqueta EXACTAMENTE lo que aqui se declara con install().
# Asi nunca se desincroniza ni "se olvida" copiar un archivo.
#
# Generar el instalador con UN comando (NSIS se AUTO-DESCARGA si falta -- el
# usuario no instala nada a mano):
#   cmake --build <build> --target installer        # -> VestaVM-<ver>-win64.exe
#   cmake --build <build> --target installer-zip     # -> VestaVM-<ver>-win64.zip
#
# Alternativa manual (si ya tienes la herramienta instalada):
#   cpack --config <build>/CPackConfig.cmake -G NSIS    # .exe bonito
#   cpack --config <build>/CPackConfig.cmake -G WIX     # .msi (requiere WiX Toolset)
#   cpack --config <build>/CPackConfig.cmake -G ZIP     # portable (sin herramientas)
#
# Layout instalado (PLANO, espejo del runtime: el ejecutable resuelve stdlib/ e
# include_lib/ relativos a su propia ubicacion).  Por COMPONENTE:
#
#   <prefix>/
#     vesta.exe                    <- [core] ejecutable principal (en el PATH)
#     libvesta_gc.a                <- [core] GC estatico para AOT (gc<T>)
#     libvesta_collections.a       <- [core] colecciones estaticas para AOT
#     libvesta_math.a              <- [core] math estatico para AOT
#     include_lib/                 <- [core] stdlib del preprocesador VPP
#     README.md, LICENSE.txt       <- [core]
#     stdlib/native/<mod>/*.dll    <- [stdlib] plugins nativos (io, math, ...)
#     stdlib/{vx,vel,port,vsh}/   <- [stdlib] modulos fuente del lenguaje
#     vesta_lsp.exe                <- [lsp] servidor LSP para editores
#     examples/vx/, examples/vsh/ <- [examples] ejemplos Vex y VSH
#     tools/                       <- [tools] scripts del lenguaje
#     vesta.dll + lib/ + include/ffi/ + cmake/  <- [sdk] embeber / plugins
#     libssl-3-x64.dll, libcrypto-3-x64.dll     <- [core] SOLO si OpenSSL no se embebio

# Las rutas de instalacion (VESTA_INSTALL_*) las fija VestaInstallDirs, que el
# CMakeLists raiz incluye ANTES que los plugins: `add_vesta_plugin` las necesita
# para saber donde va cada .dll/.so de la stdlib.
include(VestaInstallDirs)

# ---------------------------------------------------------------------------
# Reglas de instalacion (fuente de verdad) organizadas por COMPONENTE.
# El instalador NSIS ofrece marcar/desmarcar cada componente (instalacion
# personalizada).  `core` es obligatorio; el resto es opcional.
# ---------------------------------------------------------------------------

# === core (OBLIGATORIO): el lenguaje en si =================================
# El RUNTIME (vesta.exe + todo lo que el ejecutable resuelve relativo a su
# propia ubicacion: include_lib/, stdlib/, libvesta_gc.a, DLLs) se instala en
# <prefix>/bin.  Asi el acceso directo del Menu Inicio y el PATH del sistema
# (ambos gestionados por CPack, que asume `bin/`) apuntan correctamente a
# <prefix>/bin/vesta.exe y `vesta` funciona desde cualquier shell.
# Ejecutable principal instalado como vesta.exe (no vm.exe).
install(PROGRAMS "$<TARGET_FILE:vm>"
        DESTINATION "${VESTA_INSTALL_BINDIR}" RENAME "${VESTA_EXE_NAME}"
        COMPONENT core)
# stdlib del preprocesador VPP (fuente, NO binario): va en la RAIZ; el
# ejecutable en bin/ la resuelve relativo a su padre (exe_dir/../include_lib).
install(DIRECTORY "${CMAKE_SOURCE_DIR}/preprocessor/include_lib"
        DESTINATION "${VESTA_INSTALL_PRIVDIR}" COMPONENT core)
# Documentacion (LICENSE en texto plano para que el asistente lo muestre bien).
install(FILES
        "${CMAKE_SOURCE_DIR}/README.md"
        "${CMAKE_SOURCE_DIR}/LICENSE"
        DESTINATION "${VESTA_INSTALL_DOCDIR}" COMPONENT core)
# OpenSSL: si NO se embebio (fallback FireDaemon), enviar sus DLLs.  Con enlace
# estatico (VESTA_OPENSSL_STATIC) no se envia nada -- el .exe es standalone.
# Solo en Windows: en Linux OpenSSL viene de la distribucion, la dependencia la
# deduce `dpkg-shlibdeps` leyendo el binario, y no hay nada que copiar.  Sin la
# condicion, instalar el componente `core` en Linux moria buscando un .dll.
if (WIN32 AND NOT VESTA_OPENSSL_STATIC)
    install(FILES
            "$<TARGET_FILE_DIR:vm>/libssl-3-x64.dll"
            "$<TARGET_FILE_DIR:vm>/libcrypto-3-x64.dll"
            DESTINATION "${VESTA_INSTALL_BINDIR}" COMPONENT core)
endif()
# GC estatico para AOT: al compilar un programa con `gc<T>` en modo AOT, el
# enlazador interno busca libvesta_gc.a JUNTO a vesta.exe.  Sin esto, gc<T> en
# AOT falla con "no se encontro libvesta_gc.a".
if (TARGET vesta_gc)
    install(FILES "$<TARGET_FILE:vesta_gc>"
            DESTINATION "${VESTA_INSTALL_BINDIR}" COMPONENT core)
endif()
# Icono del lenguaje (para las asociaciones de ficheros .vx / .vsh).
if (WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/icono.ico")
    install(FILES "${CMAKE_SOURCE_DIR}/icono.ico"
            DESTINATION "${VESTA_INSTALL_BINDIR}" RENAME vesta.ico
            COMPONENT core)
endif()
# Variantes ESTATICAS de los plugins de stdlib (colecciones / math): el AOT las
# auto-enlaza JUNTO a vesta.exe cuando el programa las usa -> .exe standalone sin
# DLLs.  Se instalan en core (parte del toolchain AOT).
if (TARGET vesta_collections_a)
    install(FILES "$<TARGET_FILE:vesta_collections_a>"
            DESTINATION "${VESTA_INSTALL_BINDIR}" COMPONENT core)
endif()
if (TARGET vesta_math_a)
    install(FILES "$<TARGET_FILE:vesta_math_a>"
            DESTINATION "${VESTA_INSTALL_BINDIR}" COMPONENT core)
endif()

# === stdlib (opcional): biblioteca estandar del lenguaje ===================
# Modulos fuente Vesta/Vex (vx/, vel/, port/, vsh/).  Los plugins nativos
# (stdlib/native/*/*.dll) los instala add_vesta_plugin con COMPONENT stdlib.
install(DIRECTORY
        "${CMAKE_SOURCE_DIR}/stdlib/vx"
        "${CMAKE_SOURCE_DIR}/stdlib/vel"
        "${CMAKE_SOURCE_DIR}/stdlib/port"
        "${CMAKE_SOURCE_DIR}/stdlib/vsh"
        DESTINATION "${VESTA_INSTALL_PRIVDIR}/stdlib" COMPONENT stdlib
        PATTERN ".gitignore" EXCLUDE
        # La CACHE no se empaqueta.  Esta regla copia el arbol ENTERO -- no
        # tiene FILES_MATCHING como la de los ejemplos --, asi que cualquier
        # artefacto que hubiera junto a los fuentes se iba dentro del
        # instalador: en el ultimo empaquetado, 268 `.vxi`/`.vxir` de la
        # stdlib.  Se regeneran solos en la maquina del usuario y ademas
        # dependen de SU compilador, asi que enviarlos no solo sobra: manda
        # artefactos de otra version que hay que invalidar al llegar.
        #
        # `stdlib/vx` tiene su propio `vx.toml`, o sea que es un proyecto y la
        # cache se ancla AHI.  Por eso el directorio se excluye por nombre, no
        # solo por extension.
        PATTERN ".cache" EXCLUDE
        PATTERN ".vx_cache" EXCLUDE # arboles de antes del cambio de reparto
        PATTERN "*.vxi" EXCLUDE
        PATTERN "*.vxir" EXCLUDE
        PATTERN "*.vxfacts" EXCLUDE)

# === lsp (opcional): servidor de lenguaje para editores ====================
if (TARGET vesta_lsp)
    install(PROGRAMS "$<TARGET_FILE:vesta_lsp>"
            DESTINATION "${VESTA_INSTALL_BINDIR}" RENAME "${VESTA_LSP_EXE_NAME}"
            COMPONENT lsp)
endif()

# === examples (opcional): programas de ejemplo de AMBOS lenguajes ==========
# Vesta trae dos lenguajes: Vex (compilado) y VSH (scripting).
install(DIRECTORY "${CMAKE_SOURCE_DIR}/examples_codes_vx/"
        DESTINATION "${VESTA_INSTALL_DATADIR}/examples/vx" COMPONENT examples
        FILES_MATCHING
            PATTERN "*.vx"
            PATTERN "*.md"
            PATTERN "*.toml"
        # Los directorios de cache, fuera.  `FILES_MATCHING` ya filtra los
        # FICHEROS, pero CMake recorre el arbol y crea los directorios igual:
        # el instalador acababa con 38 `.cache`/`.vx_cache` VACIOS calcados de
        # la estructura de los ejemplos.
        PATTERN ".cache" EXCLUDE
        PATTERN ".vx_cache" EXCLUDE)
install(DIRECTORY "${CMAKE_SOURCE_DIR}/examples_codes_vsh/"
        DESTINATION "${VESTA_INSTALL_DATADIR}/examples/vsh" COMPONENT examples
        FILES_MATCHING
            PATTERN "*.vsh"
            PATTERN "*.md"
        PATTERN ".cache" EXCLUDE
        PATTERN ".vx_cache" EXCLUDE)

# === tools (opcional): herramientas del lenguaje ===========================
# Scripts (cobertura AOT/JIT, benchmarks, cliente de depuracion VSH).  Se
# excluyen los artefactos de build (.velb/.vel/.vx de scratch).
install(DIRECTORY "${CMAKE_SOURCE_DIR}/tools/"
        DESTINATION "${VESTA_INSTALL_DATADIR}/tools" COMPONENT tools
        FILES_MATCHING
            PATTERN "*.py"
            PATTERN "*.vsh"
            PATTERN "*.sh"
            PATTERN "*.md")

# === sdk (opcional): escribir plugins nativos ==============================
# La biblioteca embebible NO esta aqui: va en `core`, por lo que se explica
# abajo.  Aqui queda lo que solo hace falta para COMPILAR contra Vesta.
# libvesta.dll (FFI, OpenSSL + libstdc++ estaticos -> autocontenida) + header
# C + helper CMake.
if (TARGET vesta_ffi)
    # La biblioteca embebible va en CORE, y no por donde cae en el disco: es
    # PARTE DEL LENGUAJE.
    #
    # Es el compilador entero detras de una API en C, y de ahi salen dos cosas
    # que no son "desarrollo": que un programa Vesta pueda compilar Vesta
    # llamandola por FFI, y que otro lenguaje pueda compilar Vesta sin mas que
    # enlazarla.  Quitarla del paquete principal cerraria las dos.
    #
    # Lo que SI es de desarrollo -- y queda en el componente SDK -- es la
    # import library de Windows, que solo sirve para enlazar contra el DLL.
    install(TARGETS vesta_ffi
            RUNTIME DESTINATION "${VESTA_INSTALL_BINDIR}" COMPONENT core
            LIBRARY DESTINATION "${VESTA_INSTALL_BINDIR}" COMPONENT core
            ARCHIVE DESTINATION "${VESTA_INSTALL_LIBDIR}" COMPONENT sdk)
endif()
install(FILES "${CMAKE_SOURCE_DIR}/include/ffi/vesta_plugin.h"
        DESTINATION "${VESTA_INSTALL_INCDIR}/ffi" COMPONENT sdk)
install(FILES "${CMAKE_SOURCE_DIR}/cmake/VestaPlugin.cmake"
        DESTINATION "${VESTA_INSTALL_CMAKEDIR}" COMPONENT sdk)

# === enlaces en el PATH (solo fuera de Windows) ============================
# El binario de verdad vive en el arbol privado; lo que va en `/usr/bin` es un
# enlace simbolico.  `/proc/self/exe` lo RESUELVE, asi que el ejecutable se
# sigue viendo dentro de su arbol y encuentra la stdlib -- que es justo lo que
# permite no tener que compilarle ninguna ruta dentro.
#
# El enlace se crea en el arbol de instalacion (no en un script de postinst)
# para que sea el gestor de paquetes quien lo ponga y quien lo quite: un enlace
# creado a mano sobrevive a la desinstalacion y deja un `vesta` que apunta a
# nada.
if (NOT WIN32)
    # `../..` desde `bin/` remonta hasta el prefijo, y de ahi se baja al arbol
    # privado.  Relativo y no absoluto: asi el enlace sigue valiendo si alguien
    # instala con otro prefijo o mueve el arbol entero.
    install(CODE "
        set(_dst \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/bin\")
        file(MAKE_DIRECTORY \"\${_dst}\")
        file(CREATE_LINK \"../${VESTA_INSTALL_BINDIR}/${VESTA_EXE_NAME}\"
             \"\${_dst}/vesta\" SYMBOLIC)
    " COMPONENT core)
    if (TARGET vesta_lsp)
        # Con guion, que es como Debian nombra los ejecutables; el fichero real
        # conserva el guion bajo del target.
        install(CODE "
            set(_dst \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/bin\")
            file(MAKE_DIRECTORY \"\${_dst}\")
            file(CREATE_LINK \"../${VESTA_INSTALL_BINDIR}/${VESTA_LSP_EXE_NAME}\"
                 \"\${_dst}/vesta-lsp\" SYMBOLIC)
        " COMPONENT lsp)
    endif()
endif()

# ---------------------------------------------------------------------------
# Metadatos CPack (comunes a todos los generadores)
# ---------------------------------------------------------------------------
# Escapado correcto de las variables CPACK_* en el config generado (paths con
# espacios, parentesis en descripciones, etc.).  Recomendado por CMake.
set(CPACK_VERBATIM_VARIABLES ON)

set(CPACK_PACKAGE_NAME              "VestaVM")
set(CPACK_PACKAGE_VENDOR           "David Lopez T. (DesmonHak)")
set(CPACK_PACKAGE_VERSION          "${PROJECT_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR    "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR    "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH    "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
        "VestaVM: maquina virtual y compilador del lenguaje Vex (bytecode/JIT/AOT)")
set(CPACK_PACKAGE_DESCRIPTION
        "VestaVM: el compilador y la maquina virtual de los lenguajes Vex (compilado: bytecode/JIT/AOT nativo) y VSH (scripting), con su biblioteca estandar, servidor LSP, ejemplos y herramientas.")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "VestaVM")
if (WIN32)
    set(CPACK_PACKAGE_FILE_NAME "VestaVM-${PROJECT_VERSION}-win64")
else()
    set(CPACK_PACKAGE_FILE_NAME
        "VestaVM-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Empaquetar SOLO nuestros componentes.  CPack instala CADA componente de
# CPACK_COMPONENTS_ALL por separado (con CMAKE_INSTALL_COMPONENT definido), de
# modo que las reglas install() de los submodulos de terceros (keystone/
# capstone/...), que caen en el componente "Unspecified", NUNCA se disparan.  Sin
# CPACK_MONOLITHIC_INSTALL -> el instalador NSIS muestra la pagina de seleccion
# de componentes (instalacion personalizada).
set(CPACK_COMPONENTS_ALL core stdlib lsp examples tools sdk)
# El generador ZIP por defecto haria una instalacion MONOLITICA (incluiria el
# "Unspecified" de los terceros y fallaria).  Con esto, el ZIP tambien instala
# por-componente; ALL_COMPONENTS_IN_ONE agrupa todo en UN solo .zip (no uno por
# componente) y NSIS mantiene la pagina de seleccion.
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)
# Mantener la carpeta contenedora (VestaVM-<ver>-win64/) dentro del .zip para
# que al extraer no se vuelquen los archivos sueltos en el directorio actual.
# NOTA: este valor por defecto (1) es el correcto para el ZIP; para el NSIS lo
# forzamos a 0 en CPACK_PROJECT_CONFIG_FILE (si no, el .exe instalaria en
# `...\VestaVM\VestaVM-<ver>-win64\` en vez de `...\VestaVM\`).
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY 1)
# Override por-generador (NSIS=0, ZIP=1).  CPack lo ejecuta una vez por
# generador con ${CPACK_GENERATOR} fijado -> es el modo soportado de dar valores
# distintos segun el formato (un `-D` de cpack lo pisaria el CPackConfig).
set(CPACK_PROJECT_CONFIG_FILE
        "${CMAKE_SOURCE_DIR}/cmake/VestaCPackProjectConfig.cmake")

# Descripciones de cada componente (lo que ve el usuario al elegir que instalar).
set(CPACK_COMPONENT_CORE_DISPLAY_NAME     "Lenguaje Vesta (vesta.exe)")
set(CPACK_COMPONENT_CORE_DESCRIPTION
        "Compilador + maquina virtual del lenguaje Vex.  Obligatorio.")
set(CPACK_COMPONENT_CORE_REQUIRED ON)

set(CPACK_COMPONENT_STDLIB_DISPLAY_NAME   "Biblioteca estandar")
set(CPACK_COMPONENT_STDLIB_DESCRIPTION
        "Modulos de la stdlib (io, math, async, sync, mem, colecciones, strings).  Necesaria para print/IO y la mayoria de los programas.")
set(CPACK_COMPONENT_STDLIB_DEPENDS core)

set(CPACK_COMPONENT_LSP_DISPLAY_NAME      "Servidor LSP (editores)")
set(CPACK_COMPONENT_LSP_DESCRIPTION
        "vesta_lsp.exe: autocompletado, hover con Big-O, ir-a-definicion y diagnosticos en VS Code y otros editores LSP.")
set(CPACK_COMPONENT_LSP_DEPENDS core)

set(CPACK_COMPONENT_EXAMPLES_DISPLAY_NAME "Ejemplos (Vex + VSH)")
set(CPACK_COMPONENT_EXAMPLES_DESCRIPTION
        "Programas de ejemplo de los dos lenguajes de Vesta: Vex (compilado, examples/vx) y VSH (scripting, examples/vsh).")

set(CPACK_COMPONENT_TOOLS_DISPLAY_NAME    "Herramientas")
set(CPACK_COMPONENT_TOOLS_DESCRIPTION
        "Scripts del lenguaje: cobertura AOT/JIT, benchmarks y cliente de depuracion VSH.")

set(CPACK_COMPONENT_SDK_DISPLAY_NAME      "SDK (plugins / embeber)")
set(CPACK_COMPONENT_SDK_DESCRIPTION
        "libvesta.dll + header C + helper CMake para escribir plugins nativos o embeber Vesta en otros programas.")
set(CPACK_COMPONENT_SDK_DISABLED ON)   # desmarcado por defecto

# Recursos mostrados por el asistente (licencia en texto plano + readme).
# El repo mantiene UN solo fichero de licencia (LICENSE, sin extension).  El
# asistente NSIS espera un .txt, asi que generamos una copia en el build dir
# (no versionada) a partir del LICENSE canonico.
configure_file("${CMAKE_SOURCE_DIR}/LICENSE"
               "${CMAKE_BINARY_DIR}/LICENSE.txt" COPYONLY)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_BINARY_DIR}/LICENSE.txt")
set(CPACK_RESOURCE_FILE_README  "${CMAKE_SOURCE_DIR}/README.md")

# Acceso directo del Menu Inicio -> abre el REPL de Vesta.
set(CPACK_PACKAGE_EXECUTABLES "vesta" "Vesta REPL")

# Icono de la aplicacion (si existe en la raiz del repo).
set(_vesta_icon "${CMAKE_SOURCE_DIR}/icono.ico")

# ---------------------------------------------------------------------------
# NSIS  -- instalador .exe con asistente moderno (recomendado)
# ---------------------------------------------------------------------------
set(CPACK_NSIS_DISPLAY_NAME        "VestaVM ${PROJECT_VERSION}")
set(CPACK_NSIS_PACKAGE_NAME        "VestaVM ${PROJECT_VERSION}")
set(CPACK_NSIS_INSTALL_ROOT        "$PROGRAMFILES64")
# Anade <prefix> al PATH (con pagina de eleccion) -> `vesta` desde cualquier shell.
set(CPACK_NSIS_MODIFY_PATH         ON)
# NO auto-desinstalar la version previa.  El `.onInit` de CPack lee el registro
# y ejecuta el Uninstall.exe viejo; si el usuario borro la carpeta a mano, ese
# .exe ya no existe -> "Uninstall failed" + Abort (la instalacion se bloquea).
# Con esto OFF, reinstalar SOBRESCRIBE los archivos y REGENERA el registro y el
# desinstalador (auto-reparable), sin depender de un Uninstall.exe que pudo
# borrarse.  CPack no expone un hook en .onInit para hacerlo tolerante.
set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL OFF)
set(CPACK_NSIS_INSTALLED_ICON_NAME "bin\\vesta.exe")
set(CPACK_NSIS_BRANDING_TEXT       "VestaVM ${PROJECT_VERSION}")
if (EXISTS "${_vesta_icon}")
    set(CPACK_NSIS_MUI_ICON   "${_vesta_icon}")  # icono del instalador
    set(CPACK_NSIS_MUI_UNIICON "${_vesta_icon}")  # icono del desinstalador
endif()
# Imagenes opcionales del asistente (si las dejas en packaging/windows/):
#   welcome.bmp 164x314  |  header.bmp 150x57   (formato BMP)
if (EXISTS "${CMAKE_SOURCE_DIR}/packaging/windows/welcome.bmp")
    set(CPACK_NSIS_MUI_WELCOMEFINISHPAGE_BITMAP
            "${CMAKE_SOURCE_DIR}/packaging/windows/welcome.bmp")
    set(CPACK_NSIS_MUI_UNWELCOMEFINISHPAGE_BITMAP
            "${CMAKE_SOURCE_DIR}/packaging/windows/welcome.bmp")
endif()
# Enlace en el Menu Inicio al README (se abre con el editor por defecto).
set(CPACK_NSIS_MENU_LINKS
        "README.md" "VestaVM - Leeme")

# Asociaciones de ficheros .vx (fuente Vesta) y .vsh (script VestaShell) con el
# icono del lenguaje y el binario vesta.  SHCTX = HKLM si la instalacion es para
# todos (admin) o HKCU si es solo para el usuario (no-admin) -- coherente con el
# modo de instalacion elegido (RequestExecutionLevel highest en la plantilla).
# .vsh se abre ejecutando el script (--script); .vx se compila (--vesta).
set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS [==[
  ; Limpiar CUALQUIER asociacion previa (incluida una instalacion defectuosa)
  ; en AMBOS hives antes de reescribir, para un overwrite limpio: una instalacion
  ; anterior como admin pudo dejarla en HKLM y la nueva per-user escribe en HKCU.
  DeleteRegKey HKLM "Software\Classes\Vesta.vx"
  DeleteRegKey HKLM "Software\Classes\Vesta.vsh"
  DeleteRegKey HKCU "Software\Classes\Vesta.vx"
  DeleteRegKey HKCU "Software\Classes\Vesta.vsh"
  ; Windows guarda la eleccion del usuario en UserChoice (protegido); borrarlo
  ; fuerza a Explorer a reevaluar la asociacion con el ProgID nuevo.  Si esta
  ; bloqueado, el DeleteRegKey es un no-op inofensivo.
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vx\UserChoice"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vsh\UserChoice"
  WriteRegStr SHCTX "Software\Classes\.vx" "" "Vesta.vx"
  WriteRegStr SHCTX "Software\Classes\Vesta.vx" "" "Codigo fuente Vesta"
  WriteRegStr SHCTX "Software\Classes\Vesta.vx\DefaultIcon" "" "$INSTDIR\bin\vesta.ico"
  WriteRegStr SHCTX "Software\Classes\Vesta.vx\shell\open\command" "" '$\"$INSTDIR\bin\vesta.exe$\" --vesta $\"%1$\"'
  WriteRegStr SHCTX "Software\Classes\.vsh" "" "Vesta.vsh"
  WriteRegStr SHCTX "Software\Classes\Vesta.vsh" "" "Script VestaShell"
  WriteRegStr SHCTX "Software\Classes\Vesta.vsh\DefaultIcon" "" "$INSTDIR\bin\vesta.ico"
  WriteRegStr SHCTX "Software\Classes\Vesta.vsh\shell\open\command" "" '$\"$INSTDIR\bin\vesta.exe$\" --script $\"%1$\"'
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'
]==])
set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS [==[
  ; Limpiar la asociacion en AMBOS hives (una instalacion pudo dejarla en
  ; cualquiera de los dos segun fuese admin o per-user).
  DeleteRegKey HKLM "Software\Classes\Vesta.vx"
  DeleteRegKey HKLM "Software\Classes\Vesta.vsh"
  DeleteRegKey HKCU "Software\Classes\Vesta.vx"
  DeleteRegKey HKCU "Software\Classes\Vesta.vsh"
  DeleteRegValue HKLM "Software\Classes\.vx" ""
  DeleteRegValue HKLM "Software\Classes\.vsh" ""
  DeleteRegValue HKCU "Software\Classes\.vx" ""
  DeleteRegValue HKCU "Software\Classes\.vsh" ""
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vx\UserChoice"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vsh\UserChoice"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'
]==])

# ---------------------------------------------------------------------------
# WiX  -- instalador .msi (despliegue corporativo / GPO / Intune)
# ---------------------------------------------------------------------------
# UpgradeGuid FIJO: identifica el producto entre versiones (no cambiar nunca).
set(CPACK_WIX_UPGRADE_GUID    "5C9D2E14-7A3B-4F08-9E61-2B7C0A4D8F35")
set(CPACK_WIX_PROPERTY_ARPHELPLINK "https://github.com")
if (EXISTS "${_vesta_icon}")
    set(CPACK_WIX_PRODUCT_ICON "${_vesta_icon}")
endif()

# ---------------------------------------------------------------------------
# DEB / RPM  -- paquetes nativos de una distribucion de Linux
# ---------------------------------------------------------------------------
if (UNIX AND NOT APPLE)
    # Una distribucion no instala "un programa con sus opciones": instala
    # PAQUETES, y quien decide cuales es el usuario con su gestor.  Los
    # componentes se agrupan para que salgan tres, que es la division que de
    # verdad se corresponde con tres publicos distintos:
    #
    #   vesta      -- el lenguaje.  Compilador, stdlib, servidor LSP,
    #                 herramientas y ejemplos: lo mismo que instala por defecto
    #                 el asistente de Windows.  El editor no es un extra que se
    #                 anade luego, es parte de usar el lenguaje.
    #   vesta-dev  -- escribir plugins nativos: la cabecera C y el helper de
    #                 CMake.  `libvesta.so` NO esta aqui: es parte del lenguaje
    #                 y viaja en `vesta` (ver la regla que la instala).
    set(CPACK_COMPONENT_CORE_GROUP     runtime)
    set(CPACK_COMPONENT_STDLIB_GROUP   runtime)
    set(CPACK_COMPONENT_TOOLS_GROUP    runtime)
    set(CPACK_COMPONENT_EXAMPLES_GROUP runtime)
    set(CPACK_COMPONENT_LSP_GROUP      runtime)
    set(CPACK_COMPONENT_SDK_GROUP      dev)

    set(CPACK_COMPONENT_GROUP_RUNTIME_DISPLAY_NAME "vesta")
    set(CPACK_COMPONENT_GROUP_DEV_DISPLAY_NAME     "vesta-dev")

    # Sin esto los generadores DEB y RPM IGNORAN los componentes y sueltan un
    # unico paquete monolitico, por muchos grupos que se declaren.
    set(CPACK_DEB_COMPONENT_INSTALL ON)
    set(CPACK_RPM_COMPONENT_INSTALL ON)

    # El prefijo de una distribucion.  Las rutas de las reglas install() son
    # relativas a el: `lib/vesta/bin/vesta` acaba en `/usr/lib/vesta/bin/vesta`.
    set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")

    set(CPACK_DEBIAN_PACKAGE_MAINTAINER
        "David Lopez T. (DesmonHak) <anonimus.hak1.1@gmail.com>")
    set(CPACK_DEBIAN_PACKAGE_SECTION  "devel")
    set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/vesta-lang")
    # DEB-DEFAULT da el nombre canonico: vesta_1.0.0_amd64.deb.
    set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")

    set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "vesta")
    set(CPACK_DEBIAN_DEV_PACKAGE_NAME     "vesta-dev")
    # Los dos de arriba no valen para nada sin el compilador, y ademas de la
    # MISMA version: una cabecera de otra version describiria una biblioteca
    # distinta de la instalada.
    set(CPACK_DEBIAN_DEV_PACKAGE_DEPENDS "vesta (= ${PROJECT_VERSION})")

    # `dpkg-shlibdeps` LEE los binarios y deduce contra que hay que depender
    # (libc, libstdc++, libssl3).  Una lista escrita a mano envejece en silencio:
    # el dia que se enlace una biblioteca mas, el paquete se instala y falla al
    # ejecutarse.
    find_program(VESTA_DPKG_SHLIBDEPS dpkg-shlibdeps)
    if (VESTA_DPKG_SHLIBDEPS)
        set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    endif()

    # RPM-DEFAULT deja que rpmbuild aplique su nomenclatura
    # (vesta-1.0.0-1.x86_64.rpm).
    set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
    set(CPACK_RPM_PACKAGE_LICENSE "GPLv2 with runtime exception")
    set(CPACK_RPM_PACKAGE_GROUP   "Development/Languages")
    set(CPACK_RPM_RUNTIME_PACKAGE_NAME "vesta")
    set(CPACK_RPM_DEV_PACKAGE_NAME     "vesta-devel")
    set(CPACK_RPM_DEV_PACKAGE_REQUIRES "vesta = ${PROJECT_VERSION}")
    # `/usr`, `/usr/bin`, `/usr/lib` y compania los aporta el sistema base: un
    # paquete que dice ser su dueno choca con filesystem al instalarse.
    set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
        "/usr" "/usr/bin" "/usr/lib" "/usr/include" "/usr/share"
        "/usr/share/doc")
endif()

# ---------------------------------------------------------------------------
# Generador por defecto: ZIP en Windows, TGZ en el resto -- ninguno de los dos
# necesita herramientas externas.  NSIS / WIX / DEB / RPM se eligen con
# `cpack -G <generador>` o con los targets de mas abajo.
# ---------------------------------------------------------------------------
if (NOT CPACK_GENERATOR)
    if (WIN32)
        set(CPACK_GENERATOR "ZIP")
    else()
        set(CPACK_GENERATOR "TGZ")
    endif()
endif()

# Plantilla NSIS PROPIA (override de la de CPack) para habilitar instalacion
# SIN admin (per-user): cambia `RequestExecutionLevel admin` -> `highest` y el
# dir "solo yo" a %LOCALAPPDATA%\Programs.  CPack busca `NSIS.template.in` en
# CPACK_MODULE_PATH (que por defecto es CMAKE_MODULE_PATH); prependemos el dir
# con nuestra plantilla para que gane a la interna.
set(CPACK_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/nsis" ${CMAKE_MODULE_PATH})

include(CPack)

# ---------------------------------------------------------------------------
# Targets de conveniencia: generan el instalador con UN comando.  NSIS se
# AUTO-DESCARGA (portable, 2.3 MB) si no esta en el sistema -- el usuario no
# instala nada a mano (igual que la auto-descarga de OpenSSL).
#
#   cmake --build <build> --target installer        # -> VestaVM-<ver>-win64.exe
#   cmake --build <build> --target installer-zip     # -> VestaVM-<ver>-win64.zip
# ---------------------------------------------------------------------------

# Binarios que el instalador empaqueta (se construyen antes de cpack).
set(_vesta_pkg_targets vm)
foreach(_t vesta_lsp vesta_ffi vesta_gc vesta_collections_a vesta_math_a
           vesta_io vesta_math vesta_collections vx_trace)
    if (TARGET ${_t})
        list(APPEND _vesta_pkg_targets ${_t})
    endif()
endforeach()

if (WIN32)
    # .exe NSIS (con auto-descarga de NSIS si falta).
    add_custom_target(installer
            COMMAND ${CMAKE_COMMAND} -DBUILD_DIR=${CMAKE_BINARY_DIR}
                    -P "${CMAKE_SOURCE_DIR}/cmake/MakeInstallerNSIS.cmake"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            VERBATIM
            COMMENT "Generando instalador .exe (NSIS auto-descargado si no esta)")
    add_dependencies(installer ${_vesta_pkg_targets})

    # .zip portable (no requiere herramientas externas).
    add_custom_target(installer-zip
            COMMAND ${CMAKE_CPACK_COMMAND} -G ZIP
                    --config "${CMAKE_BINARY_DIR}/CPackConfig.cmake"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            VERBATIM
            COMMENT "Generando paquete .zip portable")
    add_dependencies(installer-zip ${_vesta_pkg_targets})

    # --- los paquetes de Linux, desde Windows ------------------------------
    # No compila cruzado: conduce una construccion NATIVA dentro de WSL y trae
    # los paquetes de vuelta.  Compilar cruzado de verdad necesitaria un sysroot
    # completo de Linux, y ademas daria binarios enlazados contra una version de
    # glibc elegida a ojo; construyendo dentro de la distribucion,
    # `dpkg-shlibdeps` lee los binarios y deduce las dependencias REALES.
    #
    # Los objetivos de aqui NO existen en Linux: alli se usan directamente
    # `installer-deb`, `installer-rpm` e `installer-tgz`.
    #
    # No dependen de `_vesta_pkg_targets`: lo que se empaqueta lo construye WSL,
    # y hacerles construir antes los binarios de Windows seria compilar el
    # proyecto entero dos veces para no usar la mitad.
    set(VESTA_WSL_DISTRO "" CACHE STRING
        "Distribucion de WSL con la que generar los paquetes de Linux (vacio = la predeterminada)")
    set(VESTA_LINUX_CMAKE_ARGS "" CACHE STRING
        "Argumentos extra para el cmake que corre dentro de WSL")

    foreach(_fmt DEB RPM TGZ)
        string(TOLOWER "${_fmt}" _fmt_low)
        add_custom_target(installer-linux-${_fmt_low}
                COMMAND ${CMAKE_COMMAND}
                        -DSRC_DIR=${CMAKE_SOURCE_DIR}
                        -DOUT_DIR=${CMAKE_BINARY_DIR}
                        -DDISTRO=${VESTA_WSL_DISTRO}
                        -DFORMATOS=${_fmt}
                        -DEXTRA_ARGS=${VESTA_LINUX_CMAKE_ARGS}
                        -P "${CMAKE_SOURCE_DIR}/cmake/MakeInstallerLinux.cmake"
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                VERBATIM
                COMMENT "Generando paquetes ${_fmt} de Linux dentro de WSL")
    endforeach()

    # Y el atajo: los tres de una vez.  Se apoya en los de arriba en vez de
    # pasar una lista de formatos, que al cruzar de `add_custom_target` al
    # script habria que escapar (`$<SEMICOLON>`) y es justo la clase de detalle
    # que se rompe sin avisar.  Las tres pasadas comparten el arbol de
    # construccion dentro de WSL, asi que solo la primera compila.
    add_custom_target(installer-linux
            COMMENT "Generando los paquetes de Linux (.deb + .rpm + .tar.gz) dentro de WSL")
    add_dependencies(installer-linux
            installer-linux-deb installer-linux-rpm installer-linux-tgz)
else()
    # .tar.gz portable: no necesita herramientas externas y sirve en cualquier
    # distribucion, incluidas las que no usan dpkg ni rpm.
    add_custom_target(installer-tgz
            COMMAND ${CMAKE_CPACK_COMMAND} -G TGZ
                    --config "${CMAKE_BINARY_DIR}/CPackConfig.cmake"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            VERBATIM
            COMMENT "Generando paquete .tar.gz portable")
    add_dependencies(installer-tgz ${_vesta_pkg_targets})

    # Paquetes nativos: dos .deb (vesta, vesta-dev).
    add_custom_target(installer-deb
            COMMAND ${CMAKE_CPACK_COMMAND} -G DEB
                    --config "${CMAKE_BINARY_DIR}/CPackConfig.cmake"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            VERBATIM
            COMMENT "Generando paquetes .deb (vesta + vesta-dev)")
    add_dependencies(installer-deb ${_vesta_pkg_targets})

    add_custom_target(installer-rpm
            COMMAND ${CMAKE_CPACK_COMMAND} -G RPM
                    --config "${CMAKE_BINARY_DIR}/CPackConfig.cmake"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            VERBATIM
            COMMENT "Generando paquetes .rpm (necesita rpmbuild)")
    add_dependencies(installer-rpm ${_vesta_pkg_targets})
endif()

# El target estandar `package` (creado por include(CPack)) tambien debe construir
# los binarios antes de empaquetar -- vesta_lsp/vesta_gc/vesta_ffi NO estan en el
# target `all`, asi que sin esto `cmake --build --target package` empaquetaria
# binarios obsoletos o inexistentes.
if (TARGET package)
    add_dependencies(package ${_vesta_pkg_targets})
endif()
