#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
El parche de `operator new` del asignador, validado en LOS DOS sistemas.

QUE VALIDA.  `libs/SourceCode/vesta_alloc/src/call_site.cpp` apunta de donde
viene cada reserva escribiendo un salto sobre la entrada de los ocho
`operator new`.  El mecanismo es ensamblador y depende de tres cosas que NO son
iguales en Windows y en Linux:

  - en que registro va la direccion de retorno (la convencion de llamada),
  - como se declara la informacion de desenrollado (`.seh_*` contra `.cfi_*`),
  - y si `os_protect` alinea la direccion a pagina antes de cambiar permisos.

Esa tercera ya mordio: `mprotect` EXIGE la direccion alineada y `VirtualProtect`
no, asi que la misma llamada entraba en Windows y en Linux no instalaba ninguno
de los ocho parches -- sin fallar, simplemente sin apuntar nada --.  La prueba
del asignador pasaba en Windows y nadie lo habria visto.

POR QUE AQUI.  La libreria trae su propia prueba (`vesta_alloc_test_call_site`),
y en Windows la corre el build normal.  Lo que faltaba es el OTRO lado: esto
construye la libreria SUELTA dentro de WSL y ejecuta alli la misma prueba, que
es la unica forma de que el codigo de la rama de System V se ejecute desde una
maquina de Windows.

Y de paso comprueba el guardian de LTO, que es de los que solo se puede probar
haciendo que falle: si algun dia deja de parar el configure, el parche se
quedaria a medias sin que nadie se enterase.

Uso:  python tests/aot/alloc_thunk_test.py <build_dir>
"""
import os
import shutil
import subprocess
import sys

# LADO: windows  (se lanza DESDE Windows y construye/ejecuta el lado Linux
# dentro de WSL; el lado Windows ya lo cubre el build normal)
#
# `wsl` solo existe desde Windows: lanzado desde dentro de WSL este test moriria
# por no encontrarlo, que parece un fallo suyo y no lo es.
HAY_WSL = shutil.which("wsl") is not None

# Donde se construye dentro de WSL.  En su sistema de ficheros y no en /mnt: un
# build sobre el disco de Windows visto desde Linux es mucho mas lento y no
# aporta nada a lo que se quiere comprobar.
BUILD_WSL = "/tmp/vesta_alloc_thunk_test"


def wsl(cmd):
    return subprocess.run(["wsl", "bash", "-c", cmd], capture_output=True,
                          text=True)


def ruta_wsl(win):
    """La misma carpeta, vista desde Linux."""
    p = os.path.abspath(win).replace("\\", "/")
    return "/mnt/" + p[0].lower() + p[1:].replace(":", "")


def main():
    if len(sys.argv) < 2:
        print("uso: alloc_thunk_test.py <build_dir>")
        return 2

    if not HAY_WSL:
        print("SALTADO: no hay `wsl`.  Este test se lanza DESDE Windows para "
              "cubrir el lado de Linux, que es el que el build normal no toca")
        return 77

    # tests/aot/<este fichero> -> tres niveles hasta la raiz del repositorio.
    aqui = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(aqui))
    alloc = os.path.join(repo, "libs", "SourceCode", "vesta_alloc")
    if not os.path.isdir(alloc):
        print("SALTADO: no esta el submodulo `vesta_alloc`")
        return 77
    alloc_wsl = ruta_wsl(alloc)

    if wsl("command -v cmake && command -v g++").returncode != 0:
        print("SALTADO: sin cmake y g++ en WSL no se puede construir el lado "
              "de Linux")
        return 77

    # -- 1.  El parche funciona en System V -----------------------------------
    r = wsl("cd %s && rm -rf %s && cmake -S . -B %s -DCMAKE_BUILD_TYPE=Release"
            % (alloc_wsl, BUILD_WSL, BUILD_WSL))
    if r.returncode != 0:
        print("FALLO: no se pudo configurar vesta_alloc en WSL\n%s" % r.stderr)
        return 1

    r = wsl("cmake --build %s -j8 --target vesta_alloc_test_call_site"
            % BUILD_WSL)
    if r.returncode != 0:
        print("FALLO: no compilo la prueba del thunk en Linux\n%s%s"
              % (r.stdout[-2000:], r.stderr[-2000:]))
        return 1

    r = wsl("%s/vesta_alloc_test_call_site" % BUILD_WSL)
    if r.returncode != 0:
        print("FALLO: el thunk de `operator new` no se sostiene en Linux.\n"
              "Es la rama de System V del ensamblador: otros registros, otras "
              "directivas de desenrollado, y `mprotect` exigiendo la direccion "
              "alineada.\n%s" % r.stdout)
        return 1
    print("OK: el parche de `operator new` funciona en Linux (System V)")
    for linea in r.stdout.splitlines():
        if "FALLO" in linea or "TODO OK" in linea:
            print("    %s" % linea.strip())

    # -- 2.  Y con LTO el build se PARA ---------------------------------------
    #
    # Se comprueba haciendolo fallar, que es la unica forma: un guardian que
    # deje de guardar no se nota hasta que ya es tarde.  Con LTO el enlazador
    # puede meter `operator new` dentro de sus llamantes y esas reservas dejan
    # de apuntarse -- sin fallar y sin avisar --.
    r = wsl("cd %s && rm -rf %s-lto && cmake -S . -B %s-lto "
            "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"
            % (alloc_wsl, BUILD_WSL, BUILD_WSL))
    if r.returncode == 0:
        print("FALLO: con LTO el configure paso, y no debe: el parche de "
              "`operator new` cuenta con que nadie lo inline")
        return 1
    # Se busca la CAUSA, no una frase: el mensaje esta en ingles y puede
    # reescribirse, pero si el guardian es quien paro tiene que nombrar el LTO y
    # el fichero que depende de el.  Comprobar una frase literal hace que el
    # test se ponga rojo al reescribir un comentario, y eso lo desactiva.
    salida = r.stdout + r.stderr
    if "LTO" not in salida or "call_site" not in salida:
        print("FALLO: con LTO el configure fallo, pero por otra cosa -- el "
              "mensaje no menciona LTO, asi que el guardian no es quien "
              "paro:\n%s" % r.stderr[-1500:])
        return 1
    print("OK: con LTO el build se para, y lo dice")

    wsl("rm -rf %s %s-lto" % (BUILD_WSL, BUILD_WSL))
    return 0


if __name__ == "__main__":
    sys.exit(main())
