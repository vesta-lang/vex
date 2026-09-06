#!/usr/bin/env python3
"""
@file tools/comprobar_frescura.py
@brief Que ningun objeto sea mas viejo que una cabecera de la que depende.

POR QUE EXISTE.  Un objeto que se queda atras no da error de ENLACE: los
simbolos coinciden byte a byte y solo cambia el tamano de una estructura, asi
que el enlazador esta encantado y la corrupcion sale en EJECUCION, lejos de la
causa.  Paso: `IrInstr` crecio de 184 a 200 bytes al cambiar `operands` de
`std::vector` a `SmallVector`, un objeto quedo compilado contra la version
vieja, y el JIT recorria el vector de instrucciones con el paso corto.  El
sintoma fue una violacion de segmento en una funcion que no tenia nada que ver,
y costo horas -- persiguiendo aliasing, flags y hasta el enlazador -- llegar
hasta el paso de 184.

QUE COMPRUEBA.  Ninja apunta de que cabeceras depende cada objeto.  Aqui se
compara la fecha del objeto con la de cada una de sus dependencias: si alguna es
mas nueva, ese objeto se compilo contra otra cosa.  Es GENERAL -- vale para
cualquier fichero y cualquier cabecera --, no cuesta nada en ejecucion y no hay
nada que mantener.

Lo normal es que ninja no deje que esto pase; existe para el caso en que SI
paso, que es el unico que importa.

Uso:
    python tools/comprobar_frescura.py [directorio_de_build]

Sale con 1 si encuentra alguno, y dice cual y por que cabecera.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ninja_de(build_dir):
    """@brief El ninja que construyo ESE directorio, no uno cualquiera.

    Sale de su propia cache: usar otro puede leer el registro de dependencias
    de forma distinta y dar un resultado que no es el de ese build.
    """
    cache = os.path.join(build_dir, "CMakeCache.txt")
    if os.path.isfile(cache):
        with open(cache, "r", encoding="utf-8", errors="replace") as f:
            for linea in f:
                if linea.startswith("CMAKE_MAKE_PROGRAM:"):
                    ruta = linea.split("=", 1)[1].strip()
                    if os.path.isfile(ruta):
                        return ruta
    return "ninja"


def main():
    build = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        ROOT, "cmake-build-release")
    if not os.path.isdir(build):
        sys.exit("FALLO: no encuentro el directorio de build %s" % build)

    try:
        salida = subprocess.run([ninja_de(build), "-t", "deps"], cwd=build,
                                capture_output=True, text=True,
                                errors="replace").stdout
    except OSError as e:
        sys.exit("FALLO: no pude ejecutar ninja: %s" % e)

    objeto = None
    mtime_obj = 0.0
    revisados = 0
    rancios = []      # (objeto, cabecera, cuanto mas nueva en segundos)
    for linea in salida.splitlines():
        if linea.startswith(" "):
            if objeto is None:
                continue
            dep = linea.strip()
            try:
                t = os.path.getmtime(dep)
            except OSError:
                continue      # borrada o generada: no dice nada
            if t > mtime_obj:
                rancios.append((objeto, dep, t - mtime_obj))
                objeto = None  # con una basta para senyalar el objeto
            continue
        # Cabecera del bloque: "<objeto>: #deps N, deps mtime M (VALID)"
        objeto = None
        if ": #deps" not in linea:
            continue
        nombre = linea.split(":", 1)[0]
        ruta = os.path.join(build, nombre)
        try:
            mtime_obj = os.path.getmtime(ruta)
        except OSError:
            continue          # el objeto ya no esta: lo dira el propio build
        objeto = nombre
        revisados += 1

    if not rancios:
        print("frescura: %d objetos, ninguno mas viejo que sus cabeceras"
              % revisados)
        return 0

    print("frescura: %d objetos, %d DESACTUALIZADOS" % (revisados,
                                                        len(rancios)))
    for obj, dep, delta in rancios[:20]:
        print("    %s\n        mas viejo que %s (%.0f s)"
              % (obj, os.path.relpath(dep, ROOT).replace("\\", "/"), delta))
    if len(rancios) > 20:
        print("    ... y %d mas" % (len(rancios) - 20))
    print("")
    print("Esto NO da error de enlace y corrompe en ejecucion.  Reconstruir:")
    print("    cmake --build %s --clean-first" % os.path.relpath(build, ROOT))
    return 1


if __name__ == "__main__":
    sys.exit(main())
